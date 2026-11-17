# Domainfort

**A secure-by-default identity and domain server for Linux.**

> **Status: pre-alpha. Not for production use.** There is no release. Several security-critical
> components still run in clearly labelled development modes (see [Status](docs/STATUS.md)), and
> neither Windows nor Linux computers can join a Domainfort domain yet.
>
> **Disclaimer:** use of this project, in any version, commit or form, is entirely at your own risk.
> It is provided "as is", without warranty of any kind, and the authors accept no liability for any
> damage or loss of any kind arising from its use. See [DISCLAIMER.md](DISCLAIMER.md).

## What it is

Domainfort is a Linux server that provides what a Windows Server domain controller provides to an
organisation: a central directory of users, computers and groups, network authentication, name
resolution and, later, policy and file services for domain members.

It is built for organisations that want strong identity and domain management **from day one,
without a dedicated security engineer**. The goal is *secure by default*, not *secure after
hardening*: the weak and legacy options that most real-world attacks on directory services rely
on are not switched off in a configuration file — they are simply not implemented.

- **First milestone:** a domain controller that Windows and Linux computers can join — directory,
  Kerberos, LDAP, DNS and time.
- **Long term:** a full Windows Server replacement for identity and domain services, managed
  through a command-line interface and a graphical interface, with full Linux integration.

## Two principles

### 1. Secure protocols only — weak options have no code path

Where Windows requires a Microsoft protocol, Domainfort implements only its secure subset. The
following do not exist in the code base at all; a client that asks for them is refused:

| Not implemented | Why |
|---|---|
| NTLM (all versions) and LM | pass-the-hash, relay, offline cracking |
| SMB 1 | the source of several wormable vulnerability families |
| RC4-HMAC, DES and 3DES in Kerberos | weak ciphers, downgrade, cheap offline attacks on service tickets |
| LDAP simple bind with a password in clear text | password disclosure |
| SASL DIGEST-MD5 | weak, deprecated mechanism |
| Unauthenticated RPC (except the endpoint-mapper lookup) | anonymous information gathering |
| NetBIOS, WINS, LLMNR | name-resolution poisoning |
| Netlogon without AES and sealing | the class of flaws behind well-known secure-channel attacks |
| Stored passwords in Group Policy preferences | the decryption key is public |

The full per-protocol picture is in [docs/PROTOCOLS.md](docs/PROTOCOLS.md).

### 2. Root cause first

When a weakness is found, the fix starts by naming its **class** and asking whether the
infrastructure can be changed so that the whole class becomes impossible by construction — a
type that can only exist after the check, a single chokepoint, a capability removed from the
component that should not have it, an unsafe state made unrepresentable. A local patch is used
only when that is impossible, and the remaining risk is recorded. Examples are in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Architecture in one paragraph

Domainfort is written in memory-safe Rust (`unsafe` code is forbidden in every crate) and split into
privilege-separated processes that talk over typed, bounded, local IPC, where each channel
identifies its peer by the operating system's peer credentials. **`keyd` is the only process that
holds long-term keys, and it computes rather than gives**: no key ever leaves it — the KDC, the
directory and the administration plane ask it to verify, seal or derive. **`dird`** is the policy
decision point and the single owner of the directory store; every directory write passes one
checked write path. The network fronts (KDC, LDAP, DNS, change-password) parse untrusted bytes
without holding keys or the store. Every security-relevant decision is recorded by a separate
audit process, and a state change is made only after its audit record has been acknowledged.
Cryptographic primitives are never implemented in this project: only approved libraries are
linked. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What exists today

| | |
|---|---|
| Workspace | 55 crates, roughly 365,000 lines of Rust including tests |
| Tests | about 3,550 test functions; day-to-day runs are on macOS, and the full suite, including the root-only tests, has also been run on Debian 12 at an earlier point of development |
| Fuzz targets | 51, in 29 crates, covering the network-facing parsers, the IPC codecs and the file formats; continuous fuzzing is not set up yet |
| Processes | `keyd` (key custody), `dird` (directory, policy decisions, write path), `kdc-daemon`, `ldap-front`, `dns-daemon`, `kpasswd-front`, `audit-daemon`, `admin-daemon`; tools `provision` and `keyadm` |
| Kerberos | AS and TGS with **mandatory FAST**, AES-only encryption types (RFC 3961/3962/8009 on approved primitives, verified against the RFC test vectors), change password (RFC 3244) over TCP |
| Directory | storage engine with per-record integrity protection, a first subset of the Active Directory schema, Windows security descriptors and access checks, a central policy decision point |
| LDAP | read-only engine behind a TLS 1.3 front: the rootDSE, and directory search for authenticated clients (the Kerberos bind that provides them is planned); no password binds, no writes |
| DNS | strict DNS codec; `dird` builds the authoritative zone image from the directory and the DNS front serves it |
| Principal names | one name space for every kind of principal name; `dird` signs every name resolution and the key holder verifies it before reaching any key |
| Administration | local administration plane with dual control, effect plans, a password policy, offline provisioning and a key ceremony |
| Audit | append-only, hash-chained audit log; intent acknowledged before every state change |

What is planned next, and what is waiting on external decisions, is in
[docs/STATUS.md](docs/STATUS.md).

## Build and check

Requirements: a Rust toolchain from [rustup](https://rustup.rs) (the repository pins an exact
version in `rust-toolchain.toml`), a C compiler (the TLS library used by the LDAP front builds C
code), and `python3` for the dependency licence check. See [docs/BUILDING.md](docs/BUILDING.md).

```bash
bash scripts/install-deps.sh      # fetch dependencies exactly as pinned in Cargo.lock, check licences
scripts/check-rust.sh             # fmt, clippy -D warnings, build, test (with --locked)
bash scripts/check-no-vendor.sh   # no vendored third-party code or foreign licence headers
```

The daemons run on Linux only. The code builds and the tests run on macOS and on Debian 12.

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | the Rust workspace — one crate per isolated concern; each network-facing parser is its own crate |
| `crates/*/fuzz/` | fuzz targets, in workspaces detached from the product build |
| `docs/` | public documentation (this set) |
| `scripts/` | the check gate, dependency installation, specification pinning, provenance checks |
| `tools/spec-pin/manifest.json` | the pinned specification documents (URL, revision, SHA-256) |
| `.githooks/`, `.github/workflows/` | the commit-message hook and CI |

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | processes, privileges, IPC, start order, fail-closed behaviour, the audit pipeline |
| [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) | threat model, the root-cause-first method with examples, parsers, secrets, dependencies, residual risks |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | per protocol: implemented, planned, deliberately absent |
| [docs/STATUS.md](docs/STATUS.md) | crates by area, what works end to end, what is next, what is blocked |
| [docs/BUILDING.md](docs/BUILDING.md) | toolchain, checks, test tiers, fuzzing, platforms |
| [docs/STANDARDS.md](docs/STANDARDS.md) | the standards implemented or read, grouped by area |
| [docs/KEY-CUSTODY.md](docs/KEY-CUSTODY.md) | the key holder: compute-don't-give, roles, one-time tokens, FAST, the ceremony, what a compromised KDC can and cannot do |
| [docs/PRINCIPAL-NAMESPACE.md](docs/PRINCIPAL-NAMESPACE.md) | one name space for every principal, signed name resolutions, and the name-confusion attacks it rules out |
| [docs/AD-ATTACK-CLASSES.md](docs/AD-ATTACK-CLASSES.md) | known Active Directory weakness classes and this design's answer to each, with status |
| [docs/LDAP-GSSAPI-BIND.md](docs/LDAP-GSSAPI-BIND.md) | the design of the Kerberos bind for LDAP over TLS 1.3 with channel binding (planned) |

## Reporting a vulnerability

Please report suspected vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
Do not open a public issue.

## Licence

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

## Disclaimer

Domainfort is provided **"as is", without warranty of any kind**. Any use of it — of any version,
commit, branch, tag, release, fork or copy, including old versions and versions published before
this notice was added — is **entirely at your own risk**, and you alone are responsible for its
results. To the maximum extent permitted by law, the authors and contributors accept **no
liability** for any damage or loss of any kind, direct or indirect, arising from the project or its
use. It is pre-alpha security software: do not use it to protect real systems. The full notice is
in [DISCLAIMER.md](DISCLAIMER.md); it applies together with sections 15–17 of the licence.

---

Windows, Windows Server and Active Directory are trademarks of Microsoft Corporation. Domainfort is an
independent project and is not affiliated with, sponsored by or endorsed by Microsoft.
