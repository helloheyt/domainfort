//! The keyd side of `provision first-admin-secret`: how the client is made
//! (from admind's configuration — keyd's socket, keyd's uid, the deadline)
//! and what each call's result means.
//!
//! The client is crates/ipc-keyd's `KeydClient`: before anything is sent on
//! a new connection it checks that the socket's peer uid is keyd's
//! configured uid (R50-3; A-63), so a process that took over the socket
//! path receives no password. Role::Directory may not call
//! `DescribeConfig` (docs/10 §2), so no description or caller role is
//! required of the connection — a keyd that maps this uid to another role
//! refuses `set_secret` with its uniform `Denied` before any intent (A-88;
//! as admind, docs/questions/Q-403).
//!
//! # What each outcome means ([`classify`])
//!
//! Every `set_secret` is sent with `KeydClient::call_with_fate` (A-90: the
//! password path must tell the three apart), and reported as it says:
//!
//! | outcome | password set? |
//! |---|---|
//! | keyd answered `Ok(kvno)` | yes, with that kvno (A-35: keyd chose it) |
//! | keyd answered `Err(Denied / Unavailable / RateLimited)` | no |
//! | **not sent** — connect failed, peer uid not keyd's, peer credentials unreadable, deadline before sending, unencodable | no — nothing left this process |
//! | **not performed** — keyd's shared `Refused` (`Busy`, `Unavailable`, `Malformed`, `VersionMismatch`) | no — keyd-daemon refuses a key-state change only before keyd runs it (A-88) |
//! | **outcome unknown** — the request was handed to the connection and no usable reply came | **maybe**: check keyd's audit log (it holds the intent and the outcome) before retrying |
//!
//! Spec: docs/51 §4.3 step 12; docs/10 §2, §6, §9, §10; docs/50 R50-3,
//! §3.6, §3.7; A-63; A-88; A-90 (Q-367, Q-370); docs/questions/Q-403.

use ipc::Refused;
use ipc_keyd::{
    Answer, CallFailure, ClientConfigError, Connector, KeydClient, RequestFate, TransportError,
    UnixConnector, Unserved,
};
use keyd_types::Error as KeydError;

/// How the command gets its keyd client.
pub trait KeydAccess {
    /// The connector.
    type Connector: Connector;

    /// A client for the keyd that admind's configuration names.
    ///
    /// # Errors
    /// [`ClientConfigError`] (a keyd uid of 0 — the configuration refuses
    /// it already).
    fn client(
        &mut self,
        settings: &config::AdmindSettings,
    ) -> Result<KeydClient<Self::Connector>, ClientConfigError>;
}

/// The production access: keyd's Unix socket, keyd's uid and the deadline
/// from admind's configuration.
#[derive(Debug, Default)]
pub struct UnixKeyd {
    _private: (),
}

impl UnixKeyd {
    /// The production access.
    #[must_use]
    pub fn new() -> UnixKeyd {
        UnixKeyd { _private: () }
    }
}

impl KeydAccess for UnixKeyd {
    type Connector = UnixConnector;

    /// Spec: docs/50 §3.1, §3.2, §3.6; crates/config `AdmindSettings::keyd`,
    /// `keyd_deadline`.
    fn client(
        &mut self,
        settings: &config::AdmindSettings,
    ) -> Result<KeydClient<UnixConnector>, ClientConfigError> {
        KeydClient::new(
            UnixConnector::new(settings.keyd().socket().as_path().to_path_buf()),
            settings.keyd().uid(),
            settings.keyd_deadline(),
        )
    }
}

/// How one call to keyd ended, as far as the command can know.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
    /// keyd ran the operation and answered.
    Answered(Result<T, KeydError>),
    /// Nothing reached keyd.
    NotSent(Unserved),
    /// keyd's transport refused the request: not performed (A-88).
    NotPerformed(Refused),
    /// The request was sent; keyd may or may not have performed it.
    Unknown(Unserved),
}

impl<T> Outcome<T> {
    /// `true` for `Answered(Ok(_))`.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Outcome::Answered(Ok(_)))
    }

    /// `true` only for [`Outcome::Unknown`].
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        matches!(self, Outcome::Unknown(_))
    }
}

/// Classify one `call_with_fate` result; `pick` takes keyd's answer out of
/// the operation's `Answer` variant. The client's fate decides the class
/// (it alone knows whether the request was written); a combination the
/// client never produces falls to the class that claims least (not
/// performed without a `Refused` ⇒ outcome unknown).
///
/// Spec: module documentation; crates/ipc-keyd client (`CallFailure`,
/// `RequestFate`); A-88.
pub fn classify<T>(
    result: Result<Answer, CallFailure>,
    pick: impl FnOnce(Answer) -> Option<Result<T, KeydError>>,
) -> Outcome<T> {
    match result {
        Ok(answer) => match pick(answer) {
            Some(answered) => Outcome::Answered(answered),
            None => Outcome::Unknown(Unserved::UnexpectedReply(
                ipc_keyd::ConversionError::UnexpectedReply,
            )),
        },
        Err(failure) => match (failure.fate, failure.unserved) {
            (RequestFate::NotSent, unserved) => Outcome::NotSent(unserved),
            (RequestFate::NotPerformed, Unserved::Refused(refused)) => {
                Outcome::NotPerformed(refused)
            }
            (RequestFate::NotPerformed | RequestFate::OutcomeUnknown, unserved) => {
                Outcome::Unknown(unserved)
            }
        },
    }
}

/// Why nothing was sent, as a fixed text.
/// Spec: docs/50 R50-3, §3.6; A-88 (not sent).
#[must_use]
pub const fn not_sent_text(reason: Unserved) -> &'static str {
    match reason {
        Unserved::PeerMismatch => "the keyd socket's peer uid is not the configured keyd_uid",
        Unserved::Transport(TransportError::Connect) => "the keyd socket could not be connected",
        Unserved::Transport(TransportError::PeerCredentials) => {
            "the keyd socket's peer credentials could not be read (Linux only)"
        }
        Unserved::Transport(TransportError::DeadlineExceeded) => {
            "the deadline passed before the request was sent"
        }
        Unserved::Transport(_) => "the connection to keyd failed before the request was sent",
        Unserved::Unencodable => "the request could not be encoded",
        Unserved::Refused(_) | Unserved::MalformedReply(_) | Unserved::UnexpectedReply(_) => {
            "keyd's connection check failed"
        }
    }
}

/// Why keyd did not perform a request, as a fixed text.
/// Spec: docs/10 §10 (A-88).
#[must_use]
pub const fn not_performed_text(refused: Refused) -> &'static str {
    match refused {
        Refused::Busy => "keyd is busy or cannot reach auditd",
        Refused::Malformed => "keyd refused the request as malformed",
        Refused::VersionMismatch => "keyd speaks another channel version",
        Refused::Unavailable => "keyd answered unavailable",
    }
}

/// Why an outcome is unknown, as a fixed text.
/// Spec: docs/50 §3.6, §3.7; A-88 (outcome unknown).
#[must_use]
pub const fn unknown_text(reason: Unserved) -> &'static str {
    match reason {
        Unserved::Transport(TransportError::Closed) => "keyd closed the connection",
        Unserved::Transport(TransportError::DeadlineExceeded) => "keyd did not answer in time",
        Unserved::Transport(TransportError::Framing) => "keyd's reply did not frame",
        Unserved::Transport(_) => "the connection to keyd failed",
        _ => "keyd's reply could not be read",
    }
}

/// keyd's own refusal, as a fixed text.
#[must_use]
pub const fn keyd_error_text(error: KeydError) -> &'static str {
    match error {
        KeydError::Denied => "denied",
        KeydError::Unavailable => "unavailable",
        KeydError::RateLimited => "rate limited",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyd_types::Kvno;

    fn pick(answer: Answer) -> Option<Result<Kvno, KeydError>> {
        match answer {
            Answer::SetSecret(result) => Some(result),
            _ => None,
        }
    }

    /// A-88 / A-90: the client's fate decides the class.
    #[test]
    fn the_fate_decides_the_class() {
        assert_eq!(
            classify(Ok(Answer::SetSecret(Ok(Kvno::INITIAL))), pick),
            Outcome::Answered(Ok(Kvno::INITIAL))
        );
        assert_eq!(
            classify(Ok(Answer::Ping(Ok(()))), pick),
            Outcome::Unknown(Unserved::UnexpectedReply(
                ipc_keyd::ConversionError::UnexpectedReply
            ))
        );
        let failure = |unserved, fate| CallFailure { unserved, fate };
        let connect = Unserved::Transport(TransportError::Connect);
        assert_eq!(
            classify(Err(failure(connect, RequestFate::NotSent)), pick),
            Outcome::NotSent(connect)
        );
        assert_eq!(
            classify(
                Err(failure(
                    Unserved::Refused(Refused::Busy),
                    RequestFate::NotPerformed
                )),
                pick
            ),
            Outcome::NotPerformed(Refused::Busy)
        );
        let late = Unserved::Transport(TransportError::DeadlineExceeded);
        assert_eq!(
            classify(Err(failure(late, RequestFate::OutcomeUnknown)), pick),
            Outcome::Unknown(late)
        );
        // Never produced by the client: claims least.
        assert_eq!(
            classify(Err(failure(late, RequestFate::NotPerformed)), pick),
            Outcome::Unknown(late)
        );
    }
}
