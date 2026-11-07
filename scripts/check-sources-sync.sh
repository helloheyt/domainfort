#!/usr/bin/env bash
# מאמת שכל host ב-egress-allowlist (פרט לרשם החבילות) מופיע ב-specs/SOURCES.md.
# מונע מצב שבו הסוכן יכול להגיע ל-host שאינו מקור מאושר, או להפך (docs/18 §2).
set -euo pipefail
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
allow="$root/agent-sandbox/egress-allowlist.txt"
sources="$root/specs/SOURCES.md"

# hosts של רשם החבילות מותרים ללא הופעה ב-SOURCES (הם לבנייה, לא למפרט).
pkg_hosts='crates.io static.crates.io index.crates.io'

rc=0
while read -r h; do
  [ -z "$h" ] && continue
  case " $pkg_hosts " in *" $h "*) continue;; esac
  if ! grep -qF "$h" "$sources"; then
    echo "✖ host '$h' ב-allowlist אך לא ב-specs/SOURCES.md" >&2; rc=1
  fi
done < <(grep -vE '^\s*#|^\s*$' "$allow")

[ "$rc" -eq 0 ] && echo "✓ egress-allowlist מסונכרן עם SOURCES.md."
exit "$rc"
