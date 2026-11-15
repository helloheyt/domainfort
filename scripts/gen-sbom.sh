#!/usr/bin/env bash
# phase-0 SBOM (software bill of materials) — supply-chain provenance
# (D61, R13).
#
# No-op while the workspace has no crates (nothing to enumerate). Once crates and
# dependencies exist, emits a CycloneDX SBOM. Requires: cargo install cargo-cyclonedx
set -euo pipefail
cd "$(dirname "$0")/.."

if cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"packages":\[\]'; then
  echo "phase-0: workspace has no crates — SBOM is empty, skipping."
  exit 0
fi

if ! cargo cyclonedx --version >/dev/null 2>&1; then
  echo "cargo-cyclonedx not installed (cargo install cargo-cyclonedx) — skipping SBOM." >&2
  exit 0
fi

cargo cyclonedx --format json --all
echo "SBOM generated (*.cdx.json)."
