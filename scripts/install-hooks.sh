#!/usr/bin/env bash
# מפעיל את ה-hooks של המאגר. להריץ פעם אחת אחרי git init / clone.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
chmod +x "$repo_root/.githooks/"* 2>/dev/null || true
git config core.hooksPath .githooks
echo "✓ core.hooksPath = .githooks — hook ה-commit-msg פעיל."
