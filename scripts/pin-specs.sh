#!/usr/bin/env bash
# Downloads every document in tools/spec-pin/manifest.json, computes its sha256, and fills it into the manifest.
# Downloads only from the hosts in tools/spec-pin/allowed-hosts.txt (enforcing the allowed sources:
# docs/CLEAN-ROOM.md, docs/STANDARDS.md).
# Requires: jq, curl, sha256sum (or shasum).
# Usage:  scripts/pin-specs.sh [--verify]
#   default:   fills in the sha256 **only for a document not yet pinned** and saves it to the cache. A
#              document already pinned whose content has changed is not re-pinned: the pinned sha256
#              stays, the cache is not overwritten, the new download is kept as
#              <id>.unreviewed-<sha8> and the script fails (re-pinning = a recorded decision after
#              reading the Change Tracking section; 2026-11-15). The revision field is pinned by hand
#              from the specification's landing page (a vYYYYMMDD identifier) — see docs/CLEAN-ROOM.md,
#              "Pinned specifications"; the sha256 is the real integrity anchor, and a version change
#              alters the sha256 anyway and is caught by --verify.
#   --verify:   checks that the existing sha256 still matches (for CI), without changing the manifest.
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
manifest="$root/tools/spec-pin/manifest.json"
cache="$root/tools/spec-pin/cache"
allow="$root/tools/spec-pin/allowed-hosts.txt"
mode="${1:-pin}"
mkdir -p "$cache"

command -v jq >/dev/null || { echo "jq is required." >&2; exit 2; }
sha() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }

host_allowed() {
  local h="$1"
  grep -vE '^\s*#|^\s*$' "$allow" | grep -qxF "$h"
}

tmp="$(mktemp)"
cp "$manifest" "$tmp"
rc=0

count="$(jq '.documents | length' "$manifest")"
for i in $(seq 0 $((count-1))); do
  id="$(jq -r ".documents[$i].id" "$manifest")"
  url="$(jq -r ".documents[$i].url" "$manifest")"
  host="$(printf '%s' "$url" | sed -E 's#^https?://([^/]+)/.*#\1#')"

  if ! host_allowed "$host"; then
    echo "✖ $id: host '$host' is not in tools/spec-pin/allowed-hosts.txt — skipping." >&2; rc=1; continue
  fi

  out="$cache/$id"
  dl="$(mktemp)"
  echo "• $id ← $host"
  if ! curl -fsSL "$url" -o "$dl"; then
    echo "  ✖ download failed" >&2; rc=1; rm -f "$dl"; continue
  fi
  digest="$(sha < "$dl")"
  have="$(jq -r ".documents[$i].sha256 // empty" "$manifest")"

  if [ -n "$have" ] && [ "$have" != "$digest" ]; then
    # Pinned and changed upstream: never re-pin silently, never overwrite the
    # pinned copy in the cache (both modes).
    keep="$cache/$id.unreviewed-${digest:0:8}"
    mv "$dl" "$keep"
    echo "  ✖ sha256 changed! pinned=$have current=$digest — saved to $keep for review; the pin was not changed" >&2
    rc=1; continue
  fi
  mv "$dl" "$out"
  if [ "$mode" = "--verify" ]; then
    echo "  ✓ matches"
  elif [ -z "$have" ]; then
    tmp2="$(mktemp)"
    jq --arg d "$digest" ".documents[$i].sha256 = \$d" "$tmp" > "$tmp2" && mv "$tmp2" "$tmp"
    echo "  sha256=$digest (pinned for the first time)"
  else
    echo "  ✓ matches"
  fi
done

if [ "$mode" != "--verify" ]; then
  jq --arg t "$(date -u +%FT%TZ)" '.generated_at = $t' "$tmp" > "$manifest"
  echo "✓ manifest updated. Review and commit tools/spec-pin/manifest.json."
fi
rm -f "$tmp"
exit "$rc"
