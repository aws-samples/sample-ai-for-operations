#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# One-command teardown (requirements §14.5). Removes the stack. The versioned bucket, the
# state table and the KMS key that encrypts them are RETAINED so finding history is not lost.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
: "${REGION:?Set AWS_REGION}"
STACK=NetworkRoutingDriftChecker

if [[ "${1:-}" != "--yes" ]]; then
  read -r -p "Delete stack $STACK in $REGION? Bucket, table and key are kept. [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "Aborted."; exit 1; }
fi

outputs="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --no-cli-pager \
  --query 'Stacks[0].Outputs' --output text 2>/dev/null || true)"

cd "$ROOT/infra"
npm ci --no-audit --no-fund --silent

# Cross-account hand-off: remove the link stack in the Agent Space account first, so nothing
# keeps forwarding events to a callback that is about to disappear (design D§3.3a).
LINK=NetworkRoutingDriftChecker-DevOpsAgentLink
if [[ -n "${DEVOPS_AGENT_PROFILE:-}" ]]; then
  if AWS_PROFILE="$DEVOPS_AGENT_PROFILE" aws cloudformation describe-stacks --stack-name "$LINK" \
      --region "$REGION" --no-cli-pager >/dev/null 2>&1; then
    AWS_PROFILE="$DEVOPS_AGENT_PROFILE" npx cdk destroy "$LINK" --region "$REGION" --force -c skipBundling=true
  else
    echo "No $LINK stack in the DEVOPS_AGENT_PROFILE account; skipping."
  fi
fi

npx cdk destroy "$STACK" --region "$REGION" --force -c skipBundling=true

echo
echo "Stack deleted. Retained resources (delete manually if you no longer need the history):"
echo "$outputs" | grep -E "BucketName|StateTableName" || true
echo "  - the KMS key aliased to this stack (schedule deletion only after the bucket and table are gone)"
