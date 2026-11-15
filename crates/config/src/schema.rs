//! Settings shared by several daemons, and the whole-file consistency checks.
//!
//! Every daemon has its own closed key table (docs/50 R50-15); the keys below
//! carry the same meaning in every file that has them, so one socket or one
//! account is spelled the same way in the server's file and in each client's.

use core::net::SocketAddr;
use core::time::Duration;

use crate::error::{Error, ErrorKind};
use crate::format::{Document, Located};
use crate::limits::Bound;
use crate::standard_port::StandardPort;
use crate::value::{self, is_internal, AbsolutePath, Network};

/// Key: the uid the daemon drops to. Spec: docs/50 §6.1–§6.2 (R50-14), §7.1.
pub(crate) const RUN_AS_UID: &str = "run_as_uid";
/// Key: the gid the daemon drops to. Spec: docs/50 §6.1–§6.2, §7.1.
pub(crate) const RUN_AS_GID: &str = "run_as_gid";
/// Key: path of `keyd.sock`. Spec: docs/50 §3.1.
pub(crate) const KEYD_SOCKET: &str = "keyd_socket";
/// Key: the uid keyd runs as (verified by its clients). Spec: docs/50 §3.2.
pub(crate) const KEYD_UID: &str = "keyd_uid";
/// Key: the uid dird runs as (verified by its clients). Spec: docs/50 §3.2.
pub(crate) const DIRD_UID: &str = "dird_uid";
/// Key: path of `dird-kdc.sock`. Spec: docs/50 §3.1, §3.4.
pub(crate) const DIRD_KDC_SOCKET: &str = "dird_kdc_socket";
/// Key: path of `dird-ldap.sock`. Spec: docs/50 §3.1, §4.2.
pub(crate) const DIRD_LDAP_SOCKET: &str = "dird_ldap_socket";
/// Key: path of `dird-admin.sock`. Spec: docs/50 §3.1, §2.3.
pub(crate) const DIRD_ADMIN_SOCKET: &str = "dird_admin_socket";
/// Key: path of `dird-kpasswd.sock` — one spelling for dird's file (the
/// server) and kpasswd-front's (the client; task K7). Spec: docs/53 §4.3;
/// docs/50 the channel-magic registry (`dird-kpasswd.sock | ipc-kpasswd |
/// 0x4B50`); docs/questions/Q-955 item 13.
pub(crate) const DIRD_KPASSWD_SOCKET: &str = "dird_kpasswd_socket";
/// Key: path of `dird-dns.sock` — one spelling for dird's file (the server,
/// task DN10a) and dnsd's (the client, task DN11). Spec: docs/54 §4.6;
/// docs/50 the channel-magic registry (`dird-dns.sock | ipc-dns | 0x444E`);
/// docs/questions/Q-619 items 4-5.
pub(crate) const DIRD_DNS_SOCKET: &str = "dird_dns_socket";
/// Key: path of `audit.sock`. Spec: docs/50 §3.1, §8.1 (R50-17).
pub(crate) const AUDIT_SOCKET: &str = "audit_socket";
/// Key: the uid auditd runs as (verified by its clients). Spec: docs/50 R50-3.
pub(crate) const AUDITD_UID: &str = "auditd_uid";
/// Key: path of the signed policy store, which also carries the TierMap
/// (A-36). Spec: docs/50 §7.2 ("kdc and dird load the same file").
pub(crate) const POLICY_STORE_PATH: &str = "policy_store_path";
/// Key: the zone table. Spec: docs/50 §4.1 (`Peer.src_net`), §4.2.
pub(crate) const INTERNAL_NETWORKS: &str = "internal_networks";
/// Key: server-side frame completion timeout. Spec: docs/50 §3.6.
pub(crate) const FRAME_TIMEOUT: &str = "frame_timeout";
/// Key: client deadline on the keyd channel. Spec: docs/50 §3.6.
pub(crate) const KEYD_DEADLINE: &str = "keyd_deadline";
/// Key: client deadline on the dird channel of this daemon. Spec: docs/50 §3.6.
pub(crate) const DIRD_DEADLINE: &str = "dird_deadline";

/// The account a daemon drops to: numeric uid and gid, never 0.
///
/// The daemon is started as root, binds and reads what it must, then drops to
/// this account before creating any thread (docs/50 §6.2, R50-14). Ids are
/// numeric — no name-service lookup (docs/50 §7.1) — and every uid in one file
/// is distinct (§2.4: one account per process; Q-230 item 6).
///
/// Spec: docs/50 §2.4, §6.1, §6.2, §7.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    uid: u32,
    gid: u32,
}

impl Account {
    /// The uid to drop to.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The gid to drop to.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }
}

/// A local server this daemon connects to: the path of its Unix socket and the
/// uid the server must present in its peer credentials.
///
/// R50-3: "the client also verifies the server's uid" — so a process that took
/// over the socket path receives no request (docs/50 §3.2).
///
/// Spec: docs/50 R50-3, §3.1, §3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    socket: AbsolutePath,
    uid: u32,
}

impl Endpoint {
    /// An endpoint whose path and uid the caller already registered for
    /// distinctness (an optional pair, e.g. dird's `keyd_socket` /
    /// `keyd_uid`).
    pub(crate) fn from_parts(socket: AbsolutePath, uid: u32) -> Endpoint {
        Endpoint { socket, uid }
    }

    /// The server's socket path.
    #[must_use]
    pub fn socket(&self) -> &AbsolutePath {
        &self.socket
    }

    /// The uid the server must have.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }
}

/// Whole-file distinctness: every uid and every path named once.
///
/// Spec: docs/50 §2.4 (a separate account per process), §3.1 (a socket per
/// server and channel); docs/questions/Q-214 (A-57: "a separate uid per
/// component and nothing else runs under it"); docs/questions/Q-230 items 6,
/// 16.
#[derive(Debug, Default)]
pub(crate) struct Distinct {
    ids: Vec<(u32, u32, &'static str)>,
    paths: Vec<(String, u32, &'static str)>,
}

impl Distinct {
    /// Registers a uid; a repeat is reported at the later of the two lines.
    pub(crate) fn id(&mut self, key: &'static str, id: u32, line: u32) -> Result<(), Error> {
        if let Some(&(_, seen_line, seen_key)) = self.ids.iter().find(|(seen, ..)| *seen == id) {
            return Err(later(
                line,
                key,
                seen_line,
                seen_key,
                ErrorKind::DuplicateId,
            ));
        }
        self.ids.push((id, line, key));
        Ok(())
    }

    /// Registers a path; a repeat is reported at the later of the two lines.
    pub(crate) fn path(
        &mut self,
        key: &'static str,
        path: &AbsolutePath,
        line: u32,
    ) -> Result<(), Error> {
        let text = path.as_str();
        if let Some((_, seen_line, seen_key)) = self.paths.iter().find(|(seen, ..)| seen == text) {
            return Err(later(
                line,
                key,
                *seen_line,
                seen_key,
                ErrorKind::DuplicatePath,
            ));
        }
        self.paths.push((text.to_owned(), line, key));
        Ok(())
    }
}

/// The error at whichever of two occurrences comes later in the file.
fn later(
    line: u32,
    key: &'static str,
    seen_line: u32,
    seen_key: &'static str,
    kind: ErrorKind,
) -> Error {
    if line >= seen_line {
        Error::at(line, key, kind)
    } else {
        Error::at(seen_line, seen_key, kind)
    }
}

/// A required account id, registered for distinctness.
pub(crate) fn id(doc: &Document<'_>, all: &mut Distinct, key: &'static str) -> Result<u32, Error> {
    let Located { value, line } = doc.required(key, value::account_id)?;
    all.id(key, value, line)?;
    Ok(value)
}

/// A required absolute path, registered for distinctness.
pub(crate) fn path(
    doc: &Document<'_>,
    all: &mut Distinct,
    key: &'static str,
) -> Result<AbsolutePath, Error> {
    let Located { value, line } = doc.required(key, value::absolute_path)?;
    all.path(key, &value, line)?;
    Ok(value)
}

/// The `run_as_uid` / `run_as_gid` pair. Spec: docs/50 §6.1–§6.2, §7.1.
pub(crate) fn account(doc: &Document<'_>, all: &mut Distinct) -> Result<Account, Error> {
    let uid = id(doc, all, RUN_AS_UID)?;
    // gids are not part of the uid distinctness rule (docs/50 §2.4 names
    // accounts; group sharing for socket access is §3.1 defence in depth).
    let gid = doc.required(RUN_AS_GID, value::account_id)?.value;
    Ok(Account { uid, gid })
}

/// A server endpoint from its socket key and uid key. Spec: docs/50 §3.2.
pub(crate) fn endpoint(
    doc: &Document<'_>,
    all: &mut Distinct,
    socket_key: &'static str,
    uid_key: &'static str,
) -> Result<Endpoint, Error> {
    let socket = path(doc, all, socket_key)?;
    let uid = id(doc, all, uid_key)?;
    Ok(Endpoint { socket, uid })
}

/// An optional duration limit, or its default. Spec: docs/50 §3.6, §4;
/// docs/questions/Q-230 item 4.
pub(crate) fn duration(
    doc: &Document<'_>,
    key: &'static str,
    bound: Bound,
) -> Result<Duration, Error> {
    let secs = doc
        .optional(key, |text| value::duration_secs(text, bound))?
        .map_or(bound.default, |located| located.value);
    Ok(value::seconds(secs))
}

/// Every listener address lies in a network of the zone table; reported at
/// the first list (by line) that holds one outside it. One rule for every
/// daemon that owns a network listener and the zone table: ldap-front (R14)
/// and the kdc (R50-9, task R15b), with one match (`value::is_internal`).
/// Spec: docs/52 §7 R14; A-102 on docs/questions/Q-469 (b); docs/50 R50-9
/// ("binding to internal interfaces only"), §4.1 (CIDR → Internal; UDP:
/// "binding to internal interfaces only"), §4.2; docs/questions/Q-223
/// (A-57 (a)), Q-580 (A-114), Q-632.
pub(crate) fn check_internal<const N: usize>(
    lists: [(Option<&Located<Vec<SocketAddr>>>, &'static str); N],
    internal: &[Network],
) -> Result<(), Error> {
    let mut outside: Option<(u32, &'static str)> = None;
    for (list, key) in lists {
        let Some(list) = list else {
            continue;
        };
        if list
            .value
            .iter()
            .any(|address| !is_internal(internal, address.ip()))
            && outside.is_none_or(|(line, _)| list.line < line)
        {
            outside = Some((list.line, key));
        }
    }
    match outside {
        Some((line, key)) => Err(Error::at(line, key, ErrorKind::ListenerNotInternal)),
        None => Ok(()),
    }
}

/// Every address of an advertised listener list is on its service's
/// standard port — the one copy of the port, [`StandardPort`], which the SRV
/// synthesis reads too; reported at the list's line. One rule for the four
/// files whose listeners the zone advertises: the kdc's `listen`,
/// ldap-front's `ldap_listen`, kpasswd-front's `listen` (task DN10c) and
/// dnsd's `listen` — the name server the NS record names (task DN10d).
/// Addresses stay configurable; only the port is fixed.
/// Spec: RFC 4120 §7.2.3.2; [MS-ADTS] v20261026 §6.3.2.3; RFC 1035 §4.2;
/// docs/54 §3.1; docs/questions/Q-1016 item 4 (A-176), Q-1024, Q-1025 item
/// 1 (A-178).
pub(crate) fn check_standard_port(
    list: Option<&Located<Vec<SocketAddr>>>,
    key: &'static str,
    service: StandardPort,
) -> Result<(), Error> {
    match list {
        Some(list)
            if list
                .value
                .iter()
                .any(|address| address.port() != service.number()) =>
        {
            Err(Error::at(list.line, key, ErrorKind::NonStandardPort))
        }
        _ => Ok(()),
    }
}

/// An optional integer limit, or its default, with its line (0 when absent).
/// Spec: docs/50 §3.6, §4; docs/questions/Q-230 item 4.
pub(crate) fn limit(
    doc: &Document<'_>,
    key: &'static str,
    bound: Bound,
) -> Result<Located<u32>, Error> {
    Ok(doc
        .optional(key, |text| value::bounded(text, bound))?
        .unwrap_or(Located {
            value: bound.default,
            line: 0,
        }))
}
