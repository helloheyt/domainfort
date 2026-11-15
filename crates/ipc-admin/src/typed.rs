//! The typed layer: the administrators' channel's requests and replies as
//! owned Rust values. Forwarded operations are crate ipc-dird-admin's typed
//! `Operation` (its strict decoders: UTF-8 text, GUIDs, one spelling of
//! "never"); the password of `SetPassword` is UTF-8 text in a zeroizing
//! `String` ([`Password`]), moved from the wire's zeroizing buffer without a
//! copy. Every value has exactly one encoding, so `encode(decode(b)) == b`
//! holds for everything that decodes.
//!
//! What the codec does **not** check: the password rules of [MS-SAMR]
//! 3.1.1.7.2 (characters, minimum, the account name) — admind's own check,
//! before and after dird's `BeginPasswordSet` (docs/51 §7.6, R51-5) — and
//! the semantic rules of docs/51 §11, which dird's write PEP applies.
//!
//! Spec: docs/51 §7.2, §7.3, §7.6; docs/50 §3.3 ("a single encoding per
//! value"; secret-bearing buffers zeroized); docs/10 I7; AGENTS.md §6.

use crate::channel::RefusalStatus;
use crate::wire::{AdminReply, AdminRequest, WireSetPassword};
use core::fmt;
use dtyp::{Guid, Sid};
use ipc::Secret;
use ipc_dird_admin::{Auth, Found, Operation, PendingRequestState, RequestShown, RequestSummary};
use zeroize::Zeroizing;

/// A value on the wire did not pass its strict decoder, or a typed value has
/// no form on this channel. Carries no octet.
/// Spec: docs/50 §3.3, §8.2 ("IPC errors carry a code, not content").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    /// A forwarded operation's value did not pass dird's typed decoder.
    Operation(ipc_dird_admin::ConversionError),
    /// The password is not UTF-8 (keyd takes passwords as text, docs/50
    /// §3.4).
    PasswordText,
    /// A text field of a reply is not UTF-8, or a SID did not decode.
    Reply(ipc_dird_admin::ConversionError),
    /// The operation does not travel on this channel (dird's
    /// `BeginPasswordSet` / `CompletePasswordSet`: only admind calls them,
    /// inside `SetPassword` — docs/51 §7.6).
    NotOnThisChannel,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConversionError::Operation(error) => write!(f, "invalid operation value: {error}"),
            ConversionError::PasswordText => f.write_str("password is not UTF-8"),
            ConversionError::Reply(error) => write!(f, "invalid reply value: {error}"),
            ConversionError::NotOnThisChannel => {
                f.write_str("operation does not travel on admin.sock")
            }
        }
    }
}

impl std::error::Error for ConversionError {}

/// A password on its way to keyd: zeroizing UTF-8 text. Its `Debug` prints
/// nothing of it (not even the length); no `Clone` (no silent second copy),
/// no `PartialEq` (no variable-time comparison of secret material).
/// Spec: docs/51 §7.6 ("buffers carrying a secret are `Zeroizing`"); docs/10
/// I6, I7; docs/50 §8.2; AGENTS.md §6.
pub struct Password(Zeroizing<String>);

impl Password {
    /// Wrap a password the caller already holds in a zeroizing string.
    /// Spec: docs/10 I7.
    #[must_use]
    pub fn new(text: Zeroizing<String>) -> Password {
        Password(text)
    }

    /// The text. Named so every use is visible in review.
    /// Spec: AGENTS.md §6.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// A zeroizing copy, for one keyd call (`ipc_keyd::Password` takes its
    /// text by value). The copy is allocated at its exact size, never grown.
    /// Spec: docs/10 I7; docs/50 §3.3.
    #[must_use]
    pub fn zeroizing_copy(&self) -> Zeroizing<String> {
        let mut copy = Zeroizing::new(String::with_capacity(self.0.len()));
        copy.push_str(&self.0);
        copy
    }

    /// The password from its wire buffer, moved without a copy: the octets
    /// leave the [`Secret`] by value, `String::from_utf8` takes the vector
    /// as it is, and on a UTF-8 failure the octets are handed back and
    /// wiped. Spec: docs/50 §3.3; docs/10 I7.
    fn from_secret(secret: Secret) -> Result<Password, ConversionError> {
        let mut octets = secret.into_zeroizing();
        let vector = core::mem::take(&mut *octets);
        match String::from_utf8(vector) {
            Ok(text) => Ok(Password(Zeroizing::new(text))),
            Err(error) => {
                drop(Zeroizing::new(error.into_bytes()));
                Err(ConversionError::PasswordText)
            }
        }
    }

    /// A zeroizing wire copy of the octets.
    fn to_secret(&self) -> Secret {
        Secret::from_slice(self.0.as_bytes())
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

/// `SetPassword {auth, completion, target, password}`.
/// Spec: docs/51 §5.2 row 5, §7.6; docs/questions/Q-400.
pub struct SetPassword {
    /// The requester's and approvers' raw AP-REQs, for dird's
    /// `BeginPasswordSet` (forwarded untouched).
    pub auth: Auth,
    /// The requester's second raw AP-REQ, for dird's `CompletePasswordSet`
    /// (forwarded untouched, with no approvals).
    pub completion: Vec<u8>,
    /// The account.
    pub target: Guid,
    /// The digest of the effect plan dird's `Commit {plan, BeginPasswordSet
    /// {target}}` commits to (task MA2) — from a `PlanOperation` of
    /// `BeginPasswordSet {target}`.
    pub plan: [u8; 32],
    /// The password.
    pub password: Password,
}

impl fmt::Debug for SetPassword {
    /// No AP-REQ octet and nothing of the password (docs/50 §8.2).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetPassword")
            .field("auth", &self.auth)
            .field("completion_len", &self.completion.len())
            .field("target", &self.target)
            .field("plan", &self.plan)
            .field("password", &self.password)
            .finish()
    }
}

/// Whether `operation` travels on this channel (every operation of dird's
/// channel but its two password-set steps — also not as a `Commit`: only
/// `SetPassword` sets a password here, so `pwdLastSet` is never written
/// without the `set_secret` that follows it, docs/51 §7.6; planning one,
/// `PlanOperation`, reads only and travels).
/// Spec: docs/51 §7.6; docs/questions/Q-980.
#[must_use]
pub fn forwarded(operation: &Operation) -> bool {
    let executed = match operation {
        Operation::Commit { operation, .. } => operation,
        other => other,
    };
    !matches!(
        executed,
        Operation::BeginPasswordSet { .. } | Operation::CompletePasswordSet { .. }
    )
}

/// One typed request. Spec: docs/51 §7.6; docs/50 §7.5.
#[derive(Debug)]
pub enum Request {
    /// An operation admind forwards to dird unchanged.
    Forward {
        /// The requester's and approvers' raw AP-REQs.
        auth: Auth,
        /// The operation (never a password-set step, [`forwarded`]).
        operation: Operation,
    },
    /// `SetPassword`.
    SetPassword(SetPassword),
    /// admind's health check.
    Ping,
}

impl Request {
    /// The typed request of `wire` (consumed, so the password moves).
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/51 §7.6; docs/50 §3.3.
    pub fn from_wire(wire: AdminRequest) -> Result<Request, ConversionError> {
        match wire {
            AdminRequest::Ping => Ok(Request::Ping),
            AdminRequest::Forward { auth, operation } => {
                let operation =
                    Operation::from_wire(&operation).map_err(ConversionError::Operation)?;
                if !forwarded(&operation) {
                    return Err(ConversionError::NotOnThisChannel);
                }
                Ok(Request::Forward { auth, operation })
            }
            AdminRequest::SetPassword(WireSetPassword {
                auth,
                completion,
                target,
                plan,
                password,
            }) => Ok(Request::SetPassword(SetPassword {
                auth,
                completion,
                target: Guid::from_packet(&target),
                plan,
                password: Password::from_secret(password)?,
            })),
        }
    }

    /// The wire form (the password copied into a zeroizing wire buffer).
    ///
    /// # Errors
    /// [`ConversionError::NotOnThisChannel`] for a password-set step;
    /// [`ConversionError::Operation`] for a value dird's layer cannot carry.
    ///
    /// Spec: docs/51 §7.6.
    pub fn to_wire(&self) -> Result<AdminRequest, ConversionError> {
        match self {
            Request::Ping => Ok(AdminRequest::Ping),
            Request::Forward { auth, operation } => {
                if !forwarded(operation) {
                    return Err(ConversionError::NotOnThisChannel);
                }
                Ok(AdminRequest::Forward {
                    auth: auth.clone(),
                    operation: operation.to_wire().map_err(ConversionError::Operation)?,
                })
            }
            Request::SetPassword(set) => Ok(AdminRequest::SetPassword(WireSetPassword {
                auth: set.auth.clone(),
                completion: set.completion.clone(),
                target: set.target.to_packet(),
                plan: set.plan,
                password: set.password.to_secret(),
            })),
        }
    }
}

/// The reply to a `SetPassword` whose every `set_secret` succeeded.
/// Spec: docs/51 §7.6, §9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChanged {
    /// The key versions keyd chose, in call order (`PrincipalLongterm`, then
    /// `Service` for a computer).
    pub kvnos: Vec<u32>,
    /// Whether dird accepted the `CompletePasswordSet` report. `false`: the
    /// password IS set, but dird's audit trail holds a `BeginPasswordSet`
    /// without its completion (docs/51 §9: "admind reports to the admin").
    pub completion_recorded: bool,
}

/// One typed reply. Spec: docs/51 §7.3, §7.6; docs/50 §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A create.
    Created {
        /// The objectGUID.
        guid: Guid,
        /// The objectSid (user, computer, group).
        sid: Option<Sid>,
    },
    /// `()`.
    Done,
    /// `Lookup` of a visible object.
    Found(Found),
    /// `SetPassword` carried out.
    PasswordChanged(PasswordChanged),
    /// Refused or failed (the reason is in the audit trail).
    Refused(RefusalStatus),
    /// `Ping` answered.
    Pong,
    /// dird's pending request's state (`Propose`, `Approve`; task D2-c);
    /// for a key operation its id is the id of the decision dird registers
    /// in keyd when an `Approve` completes the quorum (A-102, docs/52 §4.3).
    PendingRequest(PendingRequestState),
    /// dird's `ListRequests` answer.
    RequestList(Vec<RequestSummary>),
    /// dird's `ShowRequest` answer.
    RequestShown(Box<RequestShown>),
    /// dird's answer to a `ChangePolicy` it wrote as `policy.next` (task
    /// A16): the version root's activation installs.
    PolicyNext {
        /// The `policy_version` of `policy.next`.
        version: u64,
    },
    /// dird's effect plan (`PlanOperation`, task MA2), checked against its
    /// digest by dird's typed layer.
    Plan {
        /// The plan.
        plan: ipc_dird_admin::EffectPlan,
        /// Its digest.
        digest: [u8; 32],
    },
}

impl Reply {
    /// The typed reply of `wire`.
    ///
    /// # Errors
    /// [`ConversionError::Reply`].
    ///
    /// Spec: docs/51 §7.3, §7.6; docs/50 §3.3 (replies decoded strictly).
    pub fn from_wire(wire: &AdminReply) -> Result<Reply, ConversionError> {
        Ok(match wire {
            AdminReply::Created { guid, sid } => {
                // dird's typed layer: the GUID packet and dtyp's strict SID.
                let dird = ipc_dird_admin::AdminReply::Created {
                    guid: *guid,
                    sid: sid.clone(),
                };
                match ipc_dird_admin::Reply::from_wire(&dird).map_err(ConversionError::Reply)? {
                    ipc_dird_admin::Reply::Created { guid, sid } => Reply::Created { guid, sid },
                    _ => {
                        return Err(ConversionError::Reply(
                            ipc_dird_admin::ConversionError::UnexpectedReply,
                        ))
                    }
                }
            }
            AdminReply::Found {
                guid,
                dn,
                class,
                sid,
            } => {
                let dird = ipc_dird_admin::AdminReply::Found {
                    guid: *guid,
                    dn: dn.clone(),
                    class: class.clone(),
                    sid: sid.clone(),
                };
                match ipc_dird_admin::Reply::from_wire(&dird).map_err(ConversionError::Reply)? {
                    ipc_dird_admin::Reply::Found(found) => Reply::Found(found),
                    _ => {
                        return Err(ConversionError::Reply(
                            ipc_dird_admin::ConversionError::UnexpectedReply,
                        ))
                    }
                }
            }
            AdminReply::Done => Reply::Done,
            AdminReply::Pong => Reply::Pong,
            AdminReply::Refused(status) => Reply::Refused(*status),
            AdminReply::PasswordChanged {
                kvnos,
                completion_recorded,
            } => Reply::PasswordChanged(PasswordChanged {
                kvnos: kvnos.clone(),
                completion_recorded: *completion_recorded,
            }),
            // The request queue's replies: dird's typed layer reads them.
            AdminReply::PendingRequest(request) => {
                queue_reply(ipc_dird_admin::AdminReply::PendingRequest(request.clone()))?
            }
            AdminReply::RequestList { entries } => {
                queue_reply(ipc_dird_admin::AdminReply::RequestList {
                    entries: entries.clone(),
                })?
            }
            AdminReply::RequestShown(shown) => {
                queue_reply(ipc_dird_admin::AdminReply::RequestShown(shown.clone()))?
            }
            AdminReply::PolicyNext { version } => Reply::PolicyNext { version: *version },
            AdminReply::Plan { plan, digest } => queue_reply(ipc_dird_admin::AdminReply::Plan {
                plan: plan.clone(),
                digest: *digest,
            })?,
        })
    }

    /// The wire form.
    ///
    /// # Errors
    /// Cannot fail for a value of this type (kept fallible for symmetry with
    /// [`Reply::from_wire`]).
    ///
    /// Spec: docs/51 §7.3, §7.6.
    pub fn to_wire(&self) -> Result<AdminReply, ConversionError> {
        Ok(match self {
            Reply::Created { guid, sid } => AdminReply::Created {
                guid: guid.to_packet(),
                sid: sid.as_ref().map(Sid::encode),
            },
            Reply::Done => AdminReply::Done,
            Reply::Found(found) => AdminReply::Found {
                guid: found.guid.to_packet(),
                dn: found.dn.iter().map(|c| c.as_bytes().to_vec()).collect(),
                class: found.class.as_bytes().to_vec(),
                sid: found.sid.as_ref().map(Sid::encode),
            },
            Reply::PasswordChanged(changed) => AdminReply::PasswordChanged {
                kvnos: changed.kvnos.clone(),
                completion_recorded: changed.completion_recorded,
            },
            Reply::Refused(status) => AdminReply::Refused(*status),
            Reply::Pong => AdminReply::Pong,
            // dird's typed layer writes them, byte for byte.
            Reply::PendingRequest(state) => {
                match ipc_dird_admin::Reply::PendingRequest(state.clone())
                    .to_wire()
                    .map_err(ConversionError::Reply)?
                {
                    ipc_dird_admin::AdminReply::PendingRequest(request) => {
                        AdminReply::PendingRequest(request)
                    }
                    _ => return Err(unexpected()),
                }
            }
            Reply::RequestList(entries) => {
                match ipc_dird_admin::Reply::RequestList(entries.clone())
                    .to_wire()
                    .map_err(ConversionError::Reply)?
                {
                    ipc_dird_admin::AdminReply::RequestList { entries } => {
                        AdminReply::RequestList { entries }
                    }
                    _ => return Err(unexpected()),
                }
            }
            Reply::RequestShown(shown) => {
                match ipc_dird_admin::Reply::RequestShown(shown.clone())
                    .to_wire()
                    .map_err(ConversionError::Reply)?
                {
                    ipc_dird_admin::AdminReply::RequestShown(shown) => {
                        AdminReply::RequestShown(shown)
                    }
                    _ => return Err(unexpected()),
                }
            }
            Reply::PolicyNext { version } => AdminReply::PolicyNext { version: *version },
            Reply::Plan { plan, digest } => match (ipc_dird_admin::Reply::Plan {
                plan: plan.clone(),
                digest: *digest,
            })
            .to_wire()
            .map_err(ConversionError::Reply)?
            {
                ipc_dird_admin::AdminReply::Plan { plan, digest } => {
                    AdminReply::Plan { plan, digest }
                }
                _ => return Err(unexpected()),
            },
        })
    }

    /// The reply an administrator gets for dird's reply to a forwarded
    /// operation: the same reply, a refusal with dird's status by name.
    /// `None` for dird's `PasswordSet` (the answer to `BeginPasswordSet`,
    /// which never travels on this channel).
    /// Spec: docs/51 §7.6; crate ipc-dird-admin `Reply`.
    #[must_use]
    pub fn from_dird(reply: ipc_dird_admin::Reply) -> Option<Reply> {
        match reply {
            ipc_dird_admin::Reply::Created { guid, sid } => Some(Reply::Created { guid, sid }),
            ipc_dird_admin::Reply::Done => Some(Reply::Done),
            ipc_dird_admin::Reply::Found(found) => Some(Reply::Found(found)),
            ipc_dird_admin::Reply::Refused(status) => {
                Some(Reply::Refused(RefusalStatus::from_dird(status)))
            }
            ipc_dird_admin::Reply::Pong => Some(Reply::Pong),
            ipc_dird_admin::Reply::PendingRequest(state) => Some(Reply::PendingRequest(state)),
            ipc_dird_admin::Reply::RequestList(entries) => Some(Reply::RequestList(entries)),
            ipc_dird_admin::Reply::RequestShown(shown) => Some(Reply::RequestShown(shown)),
            ipc_dird_admin::Reply::PolicyNext { version } => Some(Reply::PolicyNext { version }),
            ipc_dird_admin::Reply::Plan { plan, digest } => Some(Reply::Plan { plan, digest }),
            ipc_dird_admin::Reply::PasswordSet(_) => None,
        }
    }
}

/// Whether `reply` is an answer `request` can receive: `Created` for a
/// create, `Found` for `Lookup`, `PendingRequest` for `Propose` / `Approve`,
/// `RequestList` for `ListRequests`, `RequestShown` for `ShowRequest` (task
/// D2-c), `PolicyNext` for `ChangePolicy` (task A16), `Done` for the
/// other forwarded operations (`Reject`, `Withdraw` included),
/// `PasswordChanged` for `SetPassword`, a refusal for any operation, `Pong`
/// for `Ping` (the closed reply column, docs/51 §7.3,
/// §7.6).
/// Spec: docs/51 §7.3, §7.6; docs/50 §3.3 (replies decoded with the same
/// strictness).
#[must_use]
pub fn answers(request: &Request, reply: &Reply) -> bool {
    match request {
        Request::Ping => matches!(reply, Reply::Pong),
        Request::SetPassword(_) => {
            matches!(reply, Reply::PasswordChanged(_) | Reply::Refused(_))
        }
        Request::Forward { operation, .. } => forward_answers(operation, reply),
    }
}

/// [`answers`] for a forwarded operation (a `Commit` is answered as the
/// operation it commits; task MA2).
fn forward_answers(operation: &Operation, reply: &Reply) -> bool {
    if let Operation::Commit {
        operation: inner, ..
    } = operation
    {
        return !matches!(reply, Reply::Plan { .. }) && forward_answers(inner, reply);
    }
    {
        match reply {
            Reply::Refused(_) => true,
            Reply::Pong | Reply::PasswordChanged(_) => false,
            Reply::Plan { .. } => matches!(operation, Operation::PlanOperation(_)),
            Reply::PolicyNext { .. } => matches!(operation, Operation::ChangePolicy { .. }),
            Reply::PendingRequest(_) => matches!(
                operation,
                Operation::Propose { .. } | Operation::Approve { .. }
            ),
            Reply::RequestList(_) => matches!(operation, Operation::ListRequests(_)),
            Reply::RequestShown(_) => matches!(operation, Operation::ShowRequest { .. }),
            Reply::Created { .. } => matches!(
                operation,
                Operation::CreateUser { .. }
                    | Operation::CreateComputer { .. }
                    | Operation::CreateGroup { .. }
                    | Operation::CreateOu { .. }
                    | Operation::CreateContainer { .. }
            ),
            Reply::Found(_) => matches!(operation, Operation::Lookup(_)),
            Reply::Done => matches!(
                operation,
                Operation::SetEnabled { .. }
                    | Operation::SetAccountExpires { .. }
                    | Operation::AddMember { .. }
                    | Operation::RemoveMember { .. }
                    | Operation::Delete { .. }
                    | Operation::Reject { .. }
                    | Operation::Withdraw { .. }
            ),
        }
    }
}

/// The "reply does not answer" conversion error.
fn unexpected() -> ConversionError {
    ConversionError::Reply(ipc_dird_admin::ConversionError::UnexpectedReply)
}

/// A request-queue reply read by dird's typed layer (the same octets).
/// Spec: crate ipc-dird-admin `Reply` (task D2-c rows).
fn queue_reply(dird: ipc_dird_admin::AdminReply) -> Result<Reply, ConversionError> {
    match ipc_dird_admin::Reply::from_wire(&dird).map_err(ConversionError::Reply)? {
        ipc_dird_admin::Reply::PendingRequest(state) => Ok(Reply::PendingRequest(state)),
        ipc_dird_admin::Reply::RequestList(entries) => Ok(Reply::RequestList(entries)),
        ipc_dird_admin::Reply::RequestShown(shown) => Ok(Reply::RequestShown(shown)),
        ipc_dird_admin::Reply::Plan { plan, digest } => Ok(Reply::Plan { plan, digest }),
        _ => Err(unexpected()),
    }
}
