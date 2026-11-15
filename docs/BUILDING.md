# Building and testing

## Requirements

| Tool | Why |
|---|---|
| Rust via [rustup](https://rustup.rs) | The repository's `rust-toolchain.toml` selects the stable channel with `rustfmt` and `clippy`; `cargo` installs it on first use. An exact version will be pinned before the first release. All crates use the 2021 edition. |
| A C compiler (`cc`, or the one named in `CC`) | The TLS cryptography provider used by the LDAP front (aws-lc-rs) compiles C code. It is the only C code in the build. CMake is not needed for the regular build. |
| `python3` | Used by the dependency licence check. |
| `jq`, `curl` | Only for verifying the pinned specification documents. |

No third-party code is stored in the repository. Dependencies are declared in `Cargo.toml`, pinned
with checksums in `Cargo.lock`, and downloaded from the official registry by whoever builds.

## Installing dependencies

```bash
bash scripts/install-deps.sh               # full: toolchain, C compiler check, fetch, licence check
bash scripts/install-deps.sh --check-only  # C compiler and licence check only, no download
```

The script never installs anything system-wide and never runs a downloaded installer. It:

1. checks that `rustup` and `cargo` are present (and tells you how to install them if not);
2. lets `rustup` provide the toolchain named in `rust-toolchain.toml`;
3. checks for a C compiler and fails with instructions if there is none;
4. downloads the dependencies exactly as pinned (`cargo fetch --locked`);
5. checks that every third-party package's licence is on the allow-list — MIT, Apache-2.0,
   BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0 — and fails otherwise;
6. runs `cargo deny check` if `cargo-deny` is installed (licences, banned packages, known
   vulnerabilities, allowed registries; configured in `deny.toml`).

## The check gate

```bash
scripts/check-rust.sh
```

runs, in order:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --all
cargo test --locked --all
```

`--locked` makes cargo refuse to proceed if the dependency graph would differ from `Cargo.lock`, so
an unreviewed change to the graph is a failure rather than a silent update. Workspace lints forbid
`unsafe` code in every crate and turn on all of Clippy's default lint groups; the gate treats every
warning as an error.

Other checks:

| Command | What it does |
|---|---|
| `bash scripts/check-no-vendor.sh` | Clean-room contamination scan: vendored code, foreign licence headers in code files, comments admitting copying, committed specification files. See [CLEAN-ROOM.md](CLEAN-ROOM.md#contamination-scan). |
| `bash scripts/check-provenance.sh <base>` | Checks the `Clean-Room:` and `Spec-Ref:` trailers of every commit since `<base>`. |
| `bash scripts/install-hooks.sh` | Enables the commit-message hook that enforces the trailers locally. |
| `bash scripts/pin-specs.sh --verify` | Re-downloads the pinned specification documents and checks their SHA-256. |
| `bash scripts/gen-sbom.sh` | Produces a CycloneDX software bill of materials (needs `cargo-cyclonedx`; skipped if it is not installed). |

CI runs the provenance and contamination checks, the specification hash check, `cargo deny`, the
Rust gate and the SBOM job on every pull request.

### Building product binaries

The daemons and tools are built per package, for example:

```bash
cargo build --release --locked -p keyd-daemon
```

Do not build product binaries with `--all-features`: some crates have test-only features that
expose test hooks, and those are meant to be enabled only by test builds. (The gate uses
`--all-features` for Clippy only, so that test code is linted too.)

| Binary | Package |
|---|---|
| `keyd-daemon` | `keyd-daemon` |
| `directory-daemon` | `directory-daemon` |
| `kdc-daemon` | `kdc-daemon` |
| `ldap-front` | `ldap-front` |
| `dns-daemon` | `dns-daemon` |
| `kpasswd-front` | `kpasswd-front` |
| `audit-daemon` | `audit-daemon` |
| `admin-daemon` | `admin-daemon` |
| `provision` | `provision` |
| `keyadm` | `keyadm` |

Each daemon takes the path of its configuration file as its only argument. The daemons are
pre-alpha and run with development key and policy sources; see [STATUS.md](STATUS.md).

## Test tiers

| Tier | What | How it runs |
|---|---|---|
| 1 — in process | Libraries and codecs: round-trip and canonical-encoding properties for every message, every bound, every unknown kind, trailing bytes, wrong versions; protocol logic against hand-built inputs, specification examples and RFC test vectors | `cargo test` — no sockets |
| 2 — real sockets | Daemons running in test threads over real Unix sockets in private temporary directories and UDP/TCP on loopback; the account-to-role tables are configured with the test's own account. Includes the end-to-end scenarios in `crates/e2e-tests`. | `cargo test` |
| 3 — root only | Process hardening (privilege drop, resource limits, no-new-privileges, capability removal) and daemons running under **distinct** accounts | Ignored by default; run as root on Linux in an isolated machine |

Every test names the source of its values: a specification section, an RFC test vector, or a
value constructed by hand for the test.

### Running the root-only tier

The root-only tests are marked ignored (or, in binaries with their own test harness, skip
themselves unless asked). Run them **as root, on Linux, in an isolated machine** — they drop
privileges, lock memory and start daemons under test accounts:

```bash
cargo test --locked --all -- --ignored
```

They need a checkout copied as root to a path made only of the characters `A-Z a-z 0-9 . _ - /`,
whose every directory from `/` is owned by root with mode 0755 (for example under `/srv`, not
under `/root`): the daemons walk their paths after dropping privileges, and the protected-file
rules refuse directories that other accounts could change. A test that finds the environment
unsuitable refuses with an explanation instead of failing obscurely.

### Scratch directories

Tests whose files are opened through the protected-file rules need a scratch directory whose
ancestors are owned by root or by the test account and are not writable by others — the system's
temporary directory does not qualify. They use `.test-scratch/` inside the workspace, or
`$HOME/.test-scratch` when the workspace path contains characters that configuration paths do not
allow (for example a space). Both are ignored by git.

## Fuzzing

There are 46 fuzz targets in 27 crates, covering the network-facing parsers, the IPC codecs and the
file formats (configuration, policy, provisioning manifest, audit log, the sealed key store
format, X.509 certificates and more). They live under `crates/<crate>/fuzz/fuzz_targets/`.

Each `fuzz/` directory is its **own** Cargo workspace, detached from the product workspace, so the
fuzzing-only dependencies never enter the product build, the gate, `cargo deny` or the SBOM. A
target is run with `cargo-fuzz` on a nightly toolchain from its crate's directory, for example:

```bash
cd crates/parse-asn1
cargo +nightly fuzz run parse_asn1_decode
```

The fuzzing harness dependencies are awaiting approval under the dependency policy, so the targets
are not yet run in CI or continuously.

## Platforms

| Platform | Status |
|---|---|
| Linux (Debian 12) | The daemons' target platform. The full suite, including the root-only tier, has been run there (at an earlier point of development; day-to-day runs are on macOS). |
| macOS | Builds; tiers 1 and 2 run. A few socket tests use a test connector in place of the Linux peer-credential path. The daemons do not run: process hardening is Linux-only and reports itself unsupported elsewhere, and a daemon that cannot harden itself exits. |

Seccomp filters, Landlock and namespaces are not used yet; see
[SECURITY-MODEL.md](SECURITY-MODEL.md#residual-risks).
