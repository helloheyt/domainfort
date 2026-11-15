#!/usr/bin/env bash
# CI provenance check: the same rule as the commit-msg hook, over a range of commits.
# Usage:  scripts/check-provenance.sh <base-ref>   (default: origin/main)
# Fails if any commit in the range breaks the trailer rules (docs/CLEAN-ROOM.md, "Commit trailers").
set -euo pipefail

base="${1:-origin/main}"
range="${base}..HEAD"

if ! git rev-parse "$base" >/dev/null 2>&1; then
  echo "check-provenance: base '$base' does not exist — checking the whole history." >&2
  range="HEAD"
fi

rc=0
while read -r sha; do
  [ -z "$sha" ] && continue
  msg="$(git log -1 --format='%B' "$sha")"
  files="$(git show --name-only --format= "$sha")"

  if ! grep -qE '^Clean-Room:[[:space:]]*\S' <<<"$msg"; then
    echo "✖ $sha: missing 'Clean-Room:'" >&2; rc=1
  fi
  if grep -qE '^(crates|src)/' <<<"$files"; then
    if ! grep -qE '^Spec-Ref:[[:space:]]*\S' <<<"$msg"; then
      echo "✖ $sha: touches product code but 'Spec-Ref:' is missing" >&2; rc=1
    fi
  fi
done < <(git rev-list "$range")

[ "$rc" -eq 0 ] && echo "✓ provenance: all commits in the range are valid."
exit "$rc"
