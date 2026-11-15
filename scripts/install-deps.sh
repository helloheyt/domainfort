#!/usr/bin/env bash
# install-deps.sh — installs the project's dependencies on the machine of whoever builds it.
#
# This is the equivalent of `npm install` against package.json:
#   Cargo.toml   ≈ package.json       — the list of dependencies (name + version range), without their code
#   Cargo.lock   ≈ package-lock.json  — the exact versions + a checksum for every package
#   cargo fetch  ≈ npm install        — downloads the packages from crates.io into the user's cache
#
# This repository does not and will not hold third-party code (docs/SECURITY-MODEL.md, "Dependencies").
# Each dependency is downloaded by whoever builds, from the official source, at the Cargo.lock version.
#
# What the script does:
#   1. Checks that rustup/cargo are installed (it does not download or run an installer itself).
#   2. Installs the Rust version pinned in rust-toolchain.toml (through rustup), and checks for a C compiler
#      (aws-lc-sys compiles C; P-21) — fails with instructions if missing, installs nothing. CMake — a warning only (A-71).
#   3. Downloads the dependencies exactly as in Cargo.lock (`cargo fetch --locked`).
#   4. Verifies that every third-party dependency has a licence from the allowed list (docs/SECURITY-MODEL.md), and fails if not.
#   5. Runs `cargo deny check` if the tool is installed (full check: licences, forbidden packages, vulnerabilities).
#
# Usage:
#   bash scripts/install-deps.sh               full installation + licence check
#   bash scripts/install-deps.sh --check-only  C toolchain + licence check (no download)
#   bash scripts/install-deps.sh --help
#
# Not included: the fuzzing dependencies (separate workspaces under crates/*/fuzz) — awaiting approval P-1.
set -euo pipefail
cd "$(dirname "$0")/.."

# The list of allowed licences — identical to deny.toml and docs/SECURITY-MODEL.md ("Dependencies"). A change = an owner decision (D70).
ALLOWED_LICENSES="MIT Apache-2.0 BSD-2-Clause BSD-3-Clause ISC Zlib Unicode-3.0"

check_only=0
case "${1:-}" in
  "") ;;
  --check-only) check_only=1 ;;
  -h|--help)
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
esac

# --- 1. rustup / cargo ---------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 || ! command -v rustup >/dev/null 2>&1; then
  cat >&2 <<'MSG'
rustup / cargo not found.
Install Rust through the system package manager or by following the official instructions at https://rustup.rs
and then run the script again. (The script does not download or run an installer itself.)
MSG
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found — it is needed for the licence check." >&2
  exit 1
fi

# --- 2. toolchain --------------------------------------------------------------
# Running cargo inside the repository makes rustup install the version pinned in rust-toolchain.toml.
echo "==> toolchain (rust-toolchain.toml)"
cargo --version
rustc --version

# --- 2b. C toolchain (aws-lc-sys compiles C code) ----------------------------------
# The crypto provider under rustls (aws-lc-rs, OD-9) builds the AWS-LC library in C through
# aws-lc-sys. The build requirements as written on the docs.rs page of aws-lc-rs 1.19.0 (Build section):
#   "Consuming projects will need a C/C++ compiler to build."
#   "Non-FIPS builds (default): CMake is never required; Bindgen is never required
#    (pre-generated bindings are provided); Go is never required."
# And on the docs.rs page of rustls 0.23.46 (the aws_lc_rs feature):
#   "Note that aws-lc-rs has additional build-time dependencies like cmake."
# Owner decision P-21: check that there is a C compiler and CMake, and fail with instructions if not.
# (CMake is checked per decision P-21 even though the aws-lc-rs page says it is not needed for the
# non-FIPS build — Q-285 item 11.) The script never installs anything itself.
# Also checked under --check-only: without a C compiler there is no build, and it is good to know before getting there.
echo "==> C toolchain (aws-lc-sys): C compiler"
cc_command="${CC:-cc}"
cc_command="${cc_command%% *}"
missing_tools=""
if ! command -v "$cc_command" >/dev/null 2>&1; then
  missing_tools="$missing_tools $cc_command"
fi
if [ -n "$missing_tools" ]; then
  cat >&2 <<MSG
Missing build tools:${missing_tools}
The TLS crypto provider (aws-lc-rs → aws-lc-sys) compiles C code at build time:
  - a C/C++ compiler (the \`cc\` command, or the one named in the CC variable) — "Consuming projects will need a C/C++
    compiler to build" (docs.rs aws-lc-rs 1.19.0);
Install it through the system package manager and run again.
(The script does not install anything itself.)
MSG
  exit 1
fi
"$cc_command" --version 2>&1 | sed -n 1p
# CMake is not needed for the regular (non-FIPS) build — "Non-FIPS builds (default): CMake is never required"
# (docs.rs aws-lc-rs 1.19.0). Decision A-71 (Q-285 item 11): only a warning if it is missing.
if command -v cmake >/dev/null 2>&1; then
  cmake --version 2>&1 | sed -n 1p
else
  echo "   (CMake not found — not needed for the regular build; needed only for the FIPS build, which is blocked on P-15)"
fi

# --- 3. Downloading the dependencies ------------------------------------------------
if [ "$check_only" -eq 0 ]; then
  echo "==> downloading the dependencies as pinned in Cargo.lock (cargo fetch --locked)"
  # --locked: fails if Cargo.lock does not match Cargo.toml — no version is "updated" silently.
  cargo fetch --locked
fi

# --- 4. Licence check --------------------------------------------------------------
echo "==> checking licences against the allowed list: $ALLOWED_LICENSES"
# (No empty array: the bash 3.2 of macOS treats it as an unset variable under set -u.)
if [ "$check_only" -eq 1 ]; then
  metadata_cmd=(cargo metadata --locked --offline --format-version 1)
else
  metadata_cmd=(cargo metadata --locked --format-version 1)
fi
"${metadata_cmd[@]}" \
  | ALLOWED_LICENSES="$ALLOWED_LICENSES" python3 -I -c '
import json, os, sys

allowed = set(os.environ["ALLOWED_LICENSES"].split())
meta = json.load(sys.stdin)

def tokens(expr):
    out, word = [], ""
    for ch in expr:
        if ch in "()":
            if word: out.append(word); word = ""
            out.append(ch)
        elif ch.isspace():
            if word: out.append(word); word = ""
        else:
            word += ch
    if word: out.append(word)
    return out

# A reduced SPDX grammar: expr := term ("OR" term)* ; term := factor ("AND" factor)* ;
# factor := "(" expr ")" | ID ["WITH" ID]. A WITH addition counts as not allowed (strict):
# the package passes only if it has another alternative that is entirely on the list.
def parse(toks):
    pos = 0
    def peek():
        return toks[pos] if pos < len(toks) else None
    def take():
        nonlocal pos
        t = peek(); pos += 1; return t
    def factor():
        t = take()
        if t == "(":
            v = expr()
            if take() != ")": raise ValueError("unbalanced")
            return v
        if t is None or t in (")", "AND", "OR", "WITH"): raise ValueError("bad token")
        if peek() == "WITH":
            take(); take()
            return False
        return t in allowed
    def term():
        v = factor()
        while peek() == "AND":
            take(); v = factor() and v
        return v
    def expr():
        v = term()
        while peek() == "OR":
            take(); v = term() or v
        return v
    v = expr()
    if peek() is not None: raise ValueError("trailing")
    return v

third_party, bad = [], []
for p in meta["packages"]:
    if p.get("source") is None:   # a crate of this repository itself (path)
        continue
    lic = p.get("license")
    ok = False
    if lic:
        try:
            ok = parse(tokens(lic))
        except ValueError:
            ok = False
    third_party.append((p["name"], p["version"], lic or "UNKNOWN"))
    if not ok:
        bad.append((p["name"], p["version"], lic or "UNKNOWN"))

for name, ver, lic in sorted(third_party):
    print(f"   {name} {ver}  [{lic}]")
print(f"   total third-party packages: {len(third_party)}")
if bad:
    print("failed: licence outside the allowed list (docs/SECURITY-MODEL.md, Dependencies):", file=sys.stderr)
    for name, ver, lic in bad:
        print(f"   {name} {ver}  [{lic}]", file=sys.stderr)
    sys.exit(1)
print("   ✓ every dependency has a licence from the allowed list.")
'

# --- 5. cargo-deny (optional) ------------------------------------------------------
if cargo deny --version >/dev/null 2>&1; then
  echo "==> cargo deny check (licences, forbidden packages, known vulnerabilities)"
  cargo deny check
else
  echo "==> cargo-deny is not installed — skipping (in CI it always runs). To install: cargo install cargo-deny"
fi

echo "==> ready. The dependencies are in the cargo cache on this machine — not inside the repository."
