#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# Upload the hybrid intent file (requirements §7). Parses it locally first so a broken file
# is caught before upload. The bucket is versioned: every upload is kept as history.
set -euo pipefail

FILE="${1:?usage: scripts/upload-intent.sh <routing-intent.yaml>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
: "${REGION:?Set AWS_REGION}"
KEY="${INTENT_OBJECT_KEY:-intent/routing-intent.yaml}"

PYTHONPATH="$ROOT/src" "$ROOT/.venv/bin/python" - "$FILE" <<'PY'
import sys
from drift_core.intent import parse
result = parse(open(sys.argv[1], encoding="utf-8").read())
if result.status != "ok":
    sys.exit("Intent file rejected:\n  " + "\n  ".join(result.errors))
print("Intent file is valid.")
PY

bucket="$(aws cloudformation describe-stacks --stack-name NetworkRoutingDriftChecker --region "$REGION" \
  --no-cli-pager --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)"
aws s3 cp "$FILE" "s3://$bucket/$KEY" --region "$REGION" --no-cli-pager
echo "Uploaded to s3://$bucket/$KEY. The next run uses it."
