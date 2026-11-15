#!/usr/bin/env bash
# Enables the repository's hooks. Run once after git init / clone.
set -euo pipefail
repo_root="$(git rev-parse --show-toplevel)"
chmod +x "$repo_root/.githooks/"* 2>/dev/null || true
git config core.hooksPath .githooks
echo "✓ core.hooksPath = .githooks — the commit-msg hook is active."
