#!/usr/bin/env bash
# phase-0 Rust gate: fmt / clippy / build / test.
#
# While the workspace has no crates (product code is gated on the interop lab /
# ⚠ verification — see docs/44-lab-build-spec.md and Cargo.toml), this is a clean
# no-op. It activates automatically the moment the first crate is added, so CI
# turns green now and enforces the real checks later without an edit.
set -euo pipefail
cd "$(dirname "$0")/.."

# Empty virtual workspace → cargo's build/clippy/test error with "no members".
if cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"packages":\[\]'; then
  echo "phase-0: workspace has no crates yet — skipping fmt/clippy/build/test."
  echo "  (product crates are gated; see docs/44-lab-build-spec.md)"
  exit 0
fi

echo "crates present — running the full Rust gate."
# --locked (A-155; docs/questions/Q-854 item 1; research r4-b IB5): the gate
# builds exactly the graph recorded in Cargo.lock. If the lock would change
# (a manifest edited without the lock, or a resolver drift), cargo refuses
# instead of silently resolving a different graph than the one reviewed.
# The full offline cache first (A-168; Q-998): `cargo fetch` without --target
# downloads the dependencies of every target, exactly as locked. Guards that
# read the worst-case graph (`cargo tree --target all --offline`) then work
# on a fresh machine or CI runner, not only where a cache happens to be warm.
cargo fetch --locked
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --all
cargo test --locked --all
