//! The operations the daemons need around the key operations: the
//! non-secret configuration at start (`describe_config`) and a health check
//! (`ping`). Neither takes a handle, touches a key, a token, a throttle or
//! the replay cache, or returns anything secret (I1); each emits exactly one
//! audit record (I8). Neither is held by the startup hold-down (Q-240 item
//! 1): the kdc asks for the configuration before it binds its ports, and
//! ping is how a daemon learns that keyd is up.
//!
//! The hold-down they are exempt from (`Keyd::admit`) refuses every Kerberos
//! operation until two clock-skew intervals after keyd's start (RFC 4120
//! 3.2.3; A-62). Two, not one: an authenticator keyd accepted just before
//! the restart, at server time ≈ S, may carry a client time up to S + skew
//! (a client clock ahead by the skew is accepted) and stays acceptable while
//! `now ≤ ctime + skew`, that is until S + 2·skew; the replay cache that
//! would have caught it was lost in the restart. One interval would leave a
//! replay window of up to one more interval; two close it (fail closed).
//! Because the configuration and the health check are answered during those
//! intervals, a kdc can start, bind its ports and answer
//! KDC_ERR_SVC_UNAVAILABLE instead of having no listener.
//!
//! Spec: docs/50 §3.4 (`DescribeConfig` — roles Kdc, Ldap; `Ping` — every
//! mapped role), §3.5, §7.5; docs/10 §2, §10, §11, §12 I1, I2, I8; RFC 4120
//! 3.2.3; docs/questions/Q-240 items 1, 3 (A-62).

use crate::audit::AuditSink;
use crate::authz::{CallerId, Operation};
use crate::config::ConfigDescription;
use crate::entropy::EntropySource;
use crate::error::{Error, Internal};
use crate::keyd::{AuditFields, Keyd};
use crate::store::KeyStore;
use krb_proto::KerberosTime;

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `describe_config`: the non-secret part of keyd's configuration
    /// ([`ConfigDescription`]: realm, enctypes, clock skew, token lifetime,
    /// ticket policy, string-to-key parameters). The kdc validates its own
    /// configuration against it before it binds its ports (docs/50 §7.5 step
    /// 4: `KdcConfig::validate`), and plans tickets keyd will accept.
    ///
    /// Roles Kdc and Ldap (docs/50 §3.4); any other role is `Denied`.
    ///
    /// Spec: docs/50 §3.4, §7.5 step 4; docs/10 §2, §12 I1, I2, I8.
    pub fn describe_config(
        &mut self,
        caller: &CallerId,
        now: &KerberosTime,
    ) -> Result<ConfigDescription, Error> {
        let fields = AuditFields::default();
        let result: Internal<ConfigDescription> = self
            .admit(caller, Operation::DescribeConfig, &[], now)
            .map(|()| self.config.description());
        self.emit(caller, Operation::DescribeConfig, now, &fields, &result);
        result.map_err(Error::from)
    }

    /// `ping`: a health check. `Ok(())` means keyd is up and the caller holds
    /// a role; it says nothing about the startup hold-down, which the held
    /// operations report themselves (`Unavailable`).
    ///
    /// Every role (docs/50 §3.4: "every mapped Role"). The IPC layer adds its
    /// own `Busy` / `Unavailable` answers (docs/50 §3.6, §3.7).
    ///
    /// Spec: docs/50 §3.4, §7.5 ("health check: op `Ping` on every
    /// channel"); docs/10 §2, §12 I2, I8.
    pub fn ping(&mut self, caller: &CallerId, now: &KerberosTime) -> Result<(), Error> {
        let fields = AuditFields::default();
        let result = self.admit(caller, Operation::Ping, &[], now);
        self.emit(caller, Operation::Ping, now, &fields, &result);
        result.map_err(Error::from)
    }
}
