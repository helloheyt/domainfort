#![forbid(unsafe_code)]
//! `provision-manifest`: the non-secret provisioning manifest (docs/51 §4.3
//! step 8; decision A-72).
//!
//! `provision domain` writes it (offline, as root, task A4); `keyadm
//! ceremony` reads it to create the krbtgt and service key sets (step 11,
//! task A5 — since task K9 also the change-password service's,
//! `kadmin/changepw`, RFC 3244 §2); `provision first-admin-secret` reads it to set the first
//! administrators' passwords (step 12, task A6). This crate holds the one
//! format, the one strict parser, the one canonical encoder, the
//! root-owned-file check, and the one derivation of every key-set handle and
//! immutable binding (A-19) — so the tools cannot disagree.
//!
//! # Format
//!
//! The configuration line format of docs/50 §7.1, parsed by crates/config's
//! public line layer `config::line_format` (one copy, A-86 follow-up — see
//! the `format` module notes): `key = value` lines, `#` comments in the
//! first column, printable ASCII only, LF after every line, ≤ 64 KiB,
//! ≤ 1024 octets a line; the closed key table [`Manifest::KEYS`], every key
//! required, none twice, nothing else. Values:
//!
//! | key | value | rule |
//! |---|---|---|
//! | `manifest_version` | `1` | exact version |
//! | `realm` | `A-Z 0-9 . -`, ≤ 255 | = the NC's DNS name in upper case (docs/47 §3.3 item 3) |
//! | `domain_sid` | `S-1-5-21-<n>-<n>-<n>` | canonical [MS-DTYP] 2.4.2.1 string, 2.4.2.4 shape |
//! | `naming_context` | `dc=<label>,…` | 1–16 labels of `A-Z a-z 0-9 -` (A-53) |
//! | `dc_fqdn` | lower-case host name | RFC 4120 §6.2.1 ("MUST be lowercase") |
//! | `krbtgt` | `<guid>:NT-SRV-INST:krbtgt/<realm>` | RFC 4120 §7.3; docs/47 §1.4 |
//! | `ldap_service` | `<guid>:NT-SRV-HST:ldap/<dc_fqdn>` | RFC 4120 §6.2.1; docs/10 §5b |
//! | `admin_service` | `<guid>:NT-SRV-HST:admind/<dc_fqdn>` | RFC 4120 §6.2.1; A-73 |
//! | `change_password_service` | `<guid>:NT-SRV-INST:kadmin/changepw` | RFC 3244 §2; RFC 4120 §6.2 (SRV-INST: a service and a fixed instance); docs/53 §5.2; task K9 |
//! | `first_admins` | 2–8 × `<guid>:NT-PRINCIPAL:<sAMAccountName>`, `", "`-separated | docs/47 §9.1; [MS-SAMR] 3.1.1.6; Q-295 |
//! | `first_admin_salts` | one salt per first administrator, in `first_admins` order, `", "`-separated | the salt `provision domain` computed with `directory_pip::account_salt` (R47-4) — the one keyadm's ceremony grant binds and `first-admin-secret` presents (A-102, docs/52 N4); required since A-105 (Q-473) |
//!
//! A `<guid>` is the lower-case `8-4-4-4-12` form ([MS-DTYP] 2.5.1.1 layout,
//! field order from [MS-DRSR] 5.16.3.16 — the A-31 route; dtyp's
//! `Guid::parse_text` / `to_text`, the workspace's one copy), never NULL, used
//! once in the manifest; it stands for the 16-octet [MS-DTYP] 2.3.4.2 packet
//! that is the object's `PrincipalId` in keyd (docs/47 §2.3). A binding is
//! written `<NAME-TYPE>:<c1>[/<c2>]` in the manifest's realm, and each
//! object's binding is checked to be exactly the one its rule fixes — the
//! manifest records the binding, and cannot record another one. For a first
//! administrator the binding's single component **is** the sAMAccountName
//! (docs/47 §1.3, R47-1), so the entry states it once.
//!
//! An example (obviously fake values; the SID is the [MS-DTYP] 2.4.2.4
//! example domain; the salts are placeholders, not the directory's salt
//! rule):
//!
//! ```text
//! # provisioning manifest (docs/51 4.3 step 8): identifiers only, no secret
//! manifest_version = 1
//! realm = EXAMPLE.TEST
//! domain_sid = S-1-5-21-1-2-3
//! naming_context = dc=example,dc=test
//! dc_fqdn = dc1.example.test
//! krbtgt = 00000000-0000-0000-0000-000000000001:NT-SRV-INST:krbtgt/EXAMPLE.TEST
//! ldap_service = 00000000-0000-0000-0000-000000000002:NT-SRV-HST:ldap/dc1.example.test
//! admin_service = 00000000-0000-0000-0000-000000000003:NT-SRV-HST:admind/dc1.example.test
//! change_password_service = 00000000-0000-0000-0000-000000000006:NT-SRV-INST:kadmin/changepw
//! first_admins = 00000000-0000-0000-0000-000000000004:NT-PRINCIPAL:alice, 00000000-0000-0000-0000-000000000005:NT-PRINCIPAL:bob
//! first_admin_salts = salt-a, salt-b
//! ```
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or panic outside tests.
//! Every bound is a named constant ([`limits`]) checked before the octets it
//! covers are copied. Errors name a line and a key, never input text. No
//! secret is ever a manifest value. A manifest file must be owned by root
//! and not writable by group or others, and is reached without following a
//! symbolic link ([`read_manifest`], through crates/protected-file).
//!
//! # Provenance
//!
//! Written only from this project's decided design and the pinned specs,
//! opened in-session: docs/51 (§4.1, §4.3, §4.4, §6, §11), docs/47 (§1.1,
//! §1.3, §1.4, §2.3, §3.3, §9.1), docs/50 (§7.1, §9), docs/10 (§1, §5b,
//! §7), PENDING-OWNER (A-19, A-31, A-53, A-55, A-60, A-72, A-73, A-77, P-1,
//! P-6, P-22), docs/questions Q-100 item 1, Q-200 item 1, Q-295; RFC 4120
//! §5.2.1, §6.1, §6.2, §6.2.1, §7.3; [MS-DTYP] v20241119 2.3.4.1, 2.3.4.2,
//! 2.4.2.1 (through dtyp), 2.4.2.4, 2.5.1.1; [MS-DRSR] v20260309 5.16.3.16;
//! [MS-SAMR] v20260427 3.1.1.6 items 8-14 (SHA-256 of each verified against
//! tools/spec-pin/manifest.json); and the public API of this project's
//! crates config, dtyp, keyd-types, krb-proto and directory-pip. No other
//! implementation and no existing provisioning or key-administration tool
//! was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/51 §4.3 step 8; docs/50 R50-15, §7.1; A-19; A-72.

mod error;
#[cfg(unix)]
mod file;
mod format;
pub mod limits;
mod manifest;
mod value;

pub use error::{Error, ErrorKind, ReadError};
#[cfg(unix)]
pub use file::{
    check_file, read_manifest, read_manifest_owned_by, FileFacts, FORBIDDEN_MODE_BITS,
    REQUIRED_OWNER_UID,
};
pub use manifest::{
    keys, FirstAdmin, KeySet, Manifest, ManifestFields, ADMIN_SERVICE_CLASS, KRBTGT_SERVICE,
    LDAP_SERVICE_CLASS,
};
pub use value::binding_text;
