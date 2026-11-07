#!/usr/bin/env bash
# בדיקת provenance ל-CI: אותו כלל כמו ה-commit-msg hook, על טווח commits.
# שימוש:  scripts/check-provenance.sh <base-ref>   (ברירת מחדל: origin/main)
# נכשל אם commit כלשהו בטווח מפר את כללי ה-trailers (AGENTS.md §4).
set -euo pipefail

base="${1:-origin/main}"
range="${base}..HEAD"

if ! git rev-parse "$base" >/dev/null 2>&1; then
  echo "check-provenance: base '$base' לא קיים — בודק את כל ההיסטוריה." >&2
  range="HEAD"
fi

rc=0
while read -r sha; do
  [ -z "$sha" ] && continue
  msg="$(git log -1 --format='%B' "$sha")"
  files="$(git show --name-only --format= "$sha")"

  if ! grep -qE '^Clean-Room:[[:space:]]*\S' <<<"$msg"; then
    echo "✖ $sha: חסר 'Clean-Room:'" >&2; rc=1
  fi
  if grep -qE '^(crates|src)/' <<<"$files"; then
    if ! grep -qE '^Spec-Ref:[[:space:]]*\S' <<<"$msg"; then
      echo "✖ $sha: נוגע בקוד מוצר אך חסר 'Spec-Ref:'" >&2; rc=1
    fi
  fi
done < <(git rev-list "$range")

[ "$rc" -eq 0 ] && echo "✓ provenance: כל ה-commits בטווח תקינים."
exit "$rc"
