//! Canonical encoder from typed messages to LDAP-BER octets.
//!
//! The output is always the one form [`crate::Profile::Canonical`] accepts:
//! definite lengths in the minimum octets (X.690 10.1), OCTET STRINGs
//! primitive, BOOLEAN TRUE as `FF`, DEFAULT values absent (RFC 4511 §5.1 —
//! all of which the §5.1 subset permits), no unrecognised components, an
//! unrecognised CHOICE alternative or unsupported operation as its tag with
//! empty contents, and a non-empty simple-bind password as the single
//! placeholder octet. This is the re-encoding the front hands to the engine
//! (docs/49 §11, R49-16) and the encoding of every response.
//!
//! SET OF elements are written in the order held (X.690 8.12.3: order is not
//! significant; RFC 4511 §5.1 does not ask for the DER ordering of 11.6).
//!
//! The encoder refuses values that would not decode back to themselves:
//! out-of-range integers, structural violations of the Filter grammar, a
//! filter deeper or larger than the decoder's bounds (which also keeps the
//! recursion bounded), and `Unrecognized` variants that carry a defined value.
//! String sizes and element counts of responses are the caller's to bound.

use crate::ber::{application, context, Writer, BOOLEAN, ENUMERATED, INTEGER, OCTET_STRING};
use crate::ber::{SEQUENCE, SET};
use crate::decode::check_next_substring;
use crate::error::{Error, Limit, Result};
use crate::limits::{MAX_FILTER_DEPTH, MAX_FILTER_NODES, MAX_INT};
use crate::message::{
    AttributeValueAssertion, AuthenticationChoice, BindRequest, BindResponse, Control,
    DerefAliases, ExtendedRequest, ExtendedResponse, Filter, LdapMessage, LdapResult,
    MatchingRuleAssertion, PartialAttribute, ProtocolOp, SaslCredentials, Scope, SearchRequest,
    SearchResultEntry, Substring, SubstringFilter, UnsupportedOp, SIMPLE_PASSWORD_PLACEHOLDER,
};

/// Highest tag number a single identifier octet can carry. Spec: X.690 8.1.2.2.
const MAX_LOW_TAG_NUMBER: u8 = 30;

/// Encode one LDAPMessage in the canonical form.
///
/// Spec: RFC 4511 §4.1.1 (LDAPMessage), §5.1 (encoding), App. B; X.690
/// clause 8 and 10.1.
pub fn encode_message(message: &LdapMessage) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.constructed(SEQUENCE, |w| {
        w.integer(INTEGER, i64::from(message.message_id.get()))?;
        protocol_op(w, &message.protocol_op)?;
        if let Some(controls) = &message.controls {
            w.constructed(context(0, true), |w| {
                controls.iter().try_for_each(|c| control(w, c))
            })?;
        }
        Ok(())
    })?;
    Ok(w.into_bytes())
}

/// Spec: RFC 4511 §4.1.1 (protocolOp), App. B (the APPLICATION tags).
fn protocol_op(w: &mut Writer, op: &ProtocolOp) -> Result<()> {
    match op {
        ProtocolOp::BindRequest(b) => w.constructed(application(0, true), |w| bind_request(w, b)),
        ProtocolOp::BindResponse(b) => w.constructed(application(1, true), |w| bind_response(w, b)),
        // "UnbindRequest ::= [APPLICATION 2] NULL". Spec: RFC 4511 §4.3;
        // X.690 8.8.
        ProtocolOp::UnbindRequest => w.element(application(2, false), &[]),
        ProtocolOp::SearchRequest(s) => {
            w.constructed(application(3, true), |w| search_request(w, s))
        }
        ProtocolOp::SearchResultEntry(e) => {
            w.constructed(application(4, true), |w| search_result_entry(w, e))
        }
        // "SearchResultDone ::= [APPLICATION 5] LDAPResult". Spec: RFC 4511
        // §4.5.2.
        ProtocolOp::SearchResultDone(r) => {
            w.constructed(application(5, true), |w| ldap_result(w, r))
        }
        // "AbandonRequest ::= [APPLICATION 16] MessageID". Spec: RFC 4511
        // §4.11.
        ProtocolOp::AbandonRequest(id) => w.integer(application(16, false), i64::from(id.get())),
        ProtocolOp::ExtendedRequest(e) => {
            w.constructed(application(23, true), |w| extended_request(w, e))
        }
        ProtocolOp::ExtendedResponse(e) => {
            w.constructed(application(24, true), |w| extended_response(w, e))
        }
        // The tag with an empty body: the canonical form of an operation whose
        // body was never decoded (A-48; docs/49 §11). DelRequest is primitive
        // (an implicitly tagged LDAPDN), the others constructed.
        ProtocolOp::Unsupported { op_tag } => {
            let constructed = *op_tag != UnsupportedOp::DelRequest;
            w.element(application(op_tag.tag_number(), constructed), &[])
        }
        // "ModifyResponse ::= [APPLICATION 7] LDAPResult" (and AddResponse 9,
        // DelResponse 11, ModifyDNResponse 13, CompareResponse 15): an
        // implicitly tagged LDAPResult SEQUENCE, hence constructed with the
        // LDAPResult components as contents. Spec: RFC 4511 §4.6-§4.10,
        // App. B; X.690 8.14.4 a), b).
        ProtocolOp::UnsupportedResponse { op, result } => w
            .constructed(application(op.response_tag_number(), true), |w| {
                ldap_result(w, result)
            }),
    }
}

/// Spec: RFC 4511 §4.2 (BindRequest, AuthenticationChoice, SaslCredentials);
/// docs/49 §2.3 (simple decoded to shape only).
fn bind_request(w: &mut Writer, b: &BindRequest) -> Result<()> {
    if !(1..=127).contains(&b.version) {
        return Err(Error::VersionOutOfRange);
    }
    w.integer(INTEGER, i64::from(b.version))?;
    w.element(OCTET_STRING, b.name.as_bytes())?;
    match &b.authentication {
        AuthenticationChoice::Simple { password_empty } => {
            let contents: &[u8] = if *password_empty {
                &[]
            } else {
                &[SIMPLE_PASSWORD_PLACEHOLDER]
            };
            w.element(context(0, false), contents)
        }
        AuthenticationChoice::Sasl(s) => w.constructed(context(3, true), |w| sasl(w, s)),
        AuthenticationChoice::Unrecognized { tag_number } => {
            let n = *tag_number;
            if n == 0 || n == 3 || n > MAX_LOW_TAG_NUMBER {
                return Err(Error::InvalidValue);
            }
            w.element(context(n, false), &[])
        }
    }
}

/// Spec: RFC 4511 §4.2 (SaslCredentials).
fn sasl(w: &mut Writer, s: &SaslCredentials) -> Result<()> {
    w.element(OCTET_STRING, s.mechanism.as_bytes())?;
    if let Some(credentials) = &s.credentials {
        w.element(OCTET_STRING, credentials)?;
    }
    Ok(())
}

/// Spec: RFC 4511 §4.2.2 (BindResponse).
fn bind_response(w: &mut Writer, b: &BindResponse) -> Result<()> {
    ldap_result(w, &b.result)?;
    if let Some(creds) = &b.server_sasl_creds {
        w.element(context(7, false), creds)?;
    }
    Ok(())
}

/// The LDAPResult components (no `referral` — R49-17).
/// Spec: RFC 4511 §4.1.9.
fn ldap_result(w: &mut Writer, r: &LdapResult) -> Result<()> {
    w.integer(ENUMERATED, i64::from(r.result_code.code()))?;
    w.element(OCTET_STRING, r.matched_dn.as_bytes())?;
    w.element(OCTET_STRING, r.diagnostic_message.as_bytes())
}

/// Spec: RFC 4511 §4.5.1 (SearchRequest).
fn search_request(w: &mut Writer, s: &SearchRequest) -> Result<()> {
    if s.size_limit > MAX_INT || s.time_limit > MAX_INT {
        return Err(Error::IntegerOutOfRange);
    }
    w.element(OCTET_STRING, s.base_object.as_bytes())?;
    let scope = match s.scope {
        Scope::BaseObject => 0,
        Scope::SingleLevel => 1,
        Scope::WholeSubtree => 2,
        Scope::Unrecognized(v) if (0..=2).contains(&v) => return Err(Error::InvalidValue),
        Scope::Unrecognized(v) => i64::from(v),
    };
    w.integer(ENUMERATED, scope)?;
    let deref = match s.deref_aliases {
        DerefAliases::NeverDerefAliases => 0,
        DerefAliases::DerefInSearching => 1,
        DerefAliases::DerefFindingBaseObj => 2,
        DerefAliases::DerefAlways => 3,
        DerefAliases::Unrecognized(v) if (0..=3).contains(&v) => return Err(Error::InvalidValue),
        DerefAliases::Unrecognized(v) => i64::from(v),
    };
    w.integer(ENUMERATED, deref)?;
    w.integer(INTEGER, i64::from(s.size_limit))?;
    w.integer(INTEGER, i64::from(s.time_limit))?;
    w.boolean(BOOLEAN, s.types_only)?;
    let mut nodes = 0;
    filter(w, &s.filter, 1, &mut nodes)?;
    w.constructed(SEQUENCE, |w| {
        s.attributes
            .iter()
            .try_for_each(|a| w.element(OCTET_STRING, a.as_bytes()))
    })
}

/// Spec: RFC 4511 §4.5.1 (Filter), §4.5.1.7; docs/49 §2.4 (the same depth and
/// element bounds as the decoder).
fn filter(w: &mut Writer, f: &Filter, depth: usize, nodes: &mut usize) -> Result<()> {
    if depth > MAX_FILTER_DEPTH {
        return Err(Error::LimitExceeded(Limit::FilterDepth));
    }
    *nodes += 1;
    if *nodes > MAX_FILTER_NODES {
        return Err(Error::LimitExceeded(Limit::FilterNodes));
    }
    match f {
        Filter::And(items) | Filter::Or(items) => {
            if items.is_empty() {
                return Err(Error::EmptySet);
            }
            let number = if matches!(f, Filter::And(_)) { 0 } else { 1 };
            w.constructed(context(number, true), |w| {
                items
                    .iter()
                    .try_for_each(|item| filter(w, item, depth + 1, nodes))
            })
        }
        // Explicit in BER. Spec: RFC 4511 §4.5.1.7.
        Filter::Not(inner) => {
            w.constructed(context(2, true), |w| filter(w, inner, depth + 1, nodes))
        }
        Filter::EqualityMatch(a) => w.constructed(context(3, true), |w| ava(w, a)),
        Filter::Substrings(s) => w.constructed(context(4, true), |w| substring_filter(w, s)),
        Filter::GreaterOrEqual(a) => w.constructed(context(5, true), |w| ava(w, a)),
        Filter::LessOrEqual(a) => w.constructed(context(6, true), |w| ava(w, a)),
        Filter::Present(d) => w.element(context(7, false), d.as_bytes()),
        Filter::ApproxMatch(a) => w.constructed(context(8, true), |w| ava(w, a)),
        Filter::ExtensibleMatch(m) => {
            w.constructed(context(9, true), |w| matching_rule_assertion(w, m))
        }
        Filter::Unrecognized { tag_number } => {
            let n = *tag_number;
            if n <= 9 || n > MAX_LOW_TAG_NUMBER {
                return Err(Error::InvalidValue);
            }
            w.element(context(n, false), &[])
        }
    }
}

/// Spec: RFC 4511 §4.1.6.
fn ava(w: &mut Writer, a: &AttributeValueAssertion) -> Result<()> {
    w.element(OCTET_STRING, a.attribute_desc.as_bytes())?;
    w.element(OCTET_STRING, &a.assertion_value)
}

/// Spec: RFC 4511 §4.5.1 (SubstringFilter), §4.5.1.7.2.
fn substring_filter(w: &mut Writer, s: &SubstringFilter) -> Result<()> {
    if s.substrings.is_empty() {
        return Err(Error::EmptySubstrings);
    }
    let mut previous = None;
    let mut any_count = 0;
    for item in &s.substrings {
        check_next_substring(previous, item, any_count)?;
        if matches!(item, Substring::Any(_)) {
            any_count += 1;
        }
        previous = Some(item);
    }
    w.element(OCTET_STRING, s.r#type.as_bytes())?;
    w.constructed(SEQUENCE, |w| {
        s.substrings.iter().try_for_each(|item| match item {
            Substring::Initial(v) => w.element(context(0, false), v),
            Substring::Any(v) => w.element(context(1, false), v),
            Substring::Final(v) => w.element(context(2, false), v),
        })
    })
}

/// Spec: RFC 4511 §4.5.1 (MatchingRuleAssertion), §4.5.1.7.7, §5.1
/// (`dnAttributes` FALSE is absent).
fn matching_rule_assertion(w: &mut Writer, m: &MatchingRuleAssertion) -> Result<()> {
    if m.matching_rule.is_none() && m.r#type.is_none() {
        return Err(Error::MissingMatchingRuleAndType);
    }
    if let Some(rule) = &m.matching_rule {
        w.element(context(1, false), rule.as_bytes())?;
    }
    if let Some(t) = &m.r#type {
        w.element(context(2, false), t.as_bytes())?;
    }
    w.element(context(3, false), &m.match_value)?;
    if m.dn_attributes {
        w.boolean(context(4, false), true)?;
    }
    Ok(())
}

/// Spec: RFC 4511 §4.5.2 (SearchResultEntry), §4.1.7 (PartialAttribute).
fn search_result_entry(w: &mut Writer, e: &SearchResultEntry) -> Result<()> {
    w.element(OCTET_STRING, e.object_name.as_bytes())?;
    w.constructed(SEQUENCE, |w| {
        e.attributes
            .iter()
            .try_for_each(|a| partial_attribute(w, a))
    })
}

/// Spec: RFC 4511 §4.1.7.
fn partial_attribute(w: &mut Writer, a: &PartialAttribute) -> Result<()> {
    w.constructed(SEQUENCE, |w| {
        w.element(OCTET_STRING, a.r#type.as_bytes())?;
        w.constructed(SET, |w| {
            a.vals.iter().try_for_each(|v| w.element(OCTET_STRING, v))
        })
    })
}

/// Spec: RFC 4511 §4.12 (ExtendedRequest).
fn extended_request(w: &mut Writer, e: &ExtendedRequest) -> Result<()> {
    w.element(context(0, false), e.request_name.as_bytes())?;
    if let Some(value) = &e.request_value {
        w.element(context(1, false), value)?;
    }
    Ok(())
}

/// Spec: RFC 4511 §4.12 (ExtendedResponse).
fn extended_response(w: &mut Writer, e: &ExtendedResponse) -> Result<()> {
    ldap_result(w, &e.result)?;
    if let Some(name) = &e.response_name {
        w.element(context(10, false), name.as_bytes())?;
    }
    if let Some(value) = &e.response_value {
        w.element(context(11, false), value)?;
    }
    Ok(())
}

/// Spec: RFC 4511 §4.1.11 (Control), §5.1 (`criticality` FALSE is absent).
fn control(w: &mut Writer, c: &Control) -> Result<()> {
    w.constructed(SEQUENCE, |w| {
        w.element(OCTET_STRING, c.control_type.as_bytes())?;
        if c.criticality {
            w.boolean(BOOLEAN, true)?;
        }
        if let Some(value) = &c.control_value {
            w.element(OCTET_STRING, value)?;
        }
        Ok(())
    })
}
