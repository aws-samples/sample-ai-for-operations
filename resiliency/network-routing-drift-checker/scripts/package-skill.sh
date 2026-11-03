#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# Package the DevOps Agent skill for "Upload skill" (design D§6.4). Writes
# dist/network-routing-drift.zip with SKILL.md at the zip root. evals/ are for testing the
# skill and are left out of the upload.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$ROOT/devops-agent-skill/network-routing-drift"
OUT="$ROOT/dist/network-routing-drift.zip"

if ! cmp -s "$ROOT/src/drift_core/investigation_schema.json" "$SKILL/references/output-schema.json"; then
  echo "ERROR: references/output-schema.json differs from src/drift_core/investigation_schema.json." >&2
  exit 1
fi
mkdir -p "$ROOT/dist"
rm -f "$OUT"
(cd "$SKILL" && zip -q -r -X "$OUT" SKILL.md README.md CHANGELOG.md references)
echo "Wrote $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes). Upload it in the Agent Space: Knowledge → Skills → Add skill."
