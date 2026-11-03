#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# Post-deploy smoke test (requirements §14.5): starts an ad-hoc run limited to one Region,
# waits for it, and asserts the execution succeeded and the report was published to SNS.
# Ad-hoc runs never move the lookback marker. Read-only apart from starting the execution.
set -euo pipefail

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
: "${REGION:?Set AWS_REGION}"
SMOKE_REGION="${1:-$REGION}"
STACK=NetworkRoutingDriftChecker

sm_arn="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --no-cli-pager \
  --query "Stacks[0].Outputs[?OutputKey=='StateMachineArn'].OutputValue" --output text)"
[[ -n "$sm_arn" && "$sm_arn" != "None" ]] || { echo "Stack $STACK not found in $REGION"; exit 1; }

exec_arn="$(aws stepfunctions start-execution --region "$REGION" --no-cli-pager \
  --state-machine-arn "$sm_arn" --name "smoke-$(date -u +%Y%m%dT%H%M%S)" \
  --input "{\"regions\": [\"$SMOKE_REGION\"]}" --query executionArn --output text)"
echo "Started $exec_arn (Region scope: $SMOKE_REGION)"

for _ in $(seq 1 90); do
  status="$(aws stepfunctions describe-execution --region "$REGION" --no-cli-pager \
    --execution-arn "$exec_arn" --query status --output text)"
  [[ "$status" != "RUNNING" ]] && break
  sleep 10
done
echo "Execution status: $status"
[[ "$status" == "SUCCEEDED" ]] || { echo "FAIL: execution did not succeed"; exit 1; }

published="$(aws stepfunctions get-execution-history --region "$REGION" --no-cli-pager \
  --execution-arn "$exec_arn" --max-items 500 \
  --query "events[?type=='TaskStateExited' && stateExitedEventDetails.name=='Publish'] | length(@)" --output text)"
[[ "$published" == "1" ]] || { echo "FAIL: report was not published"; exit 1; }
echo "PASS: run completed and the report was published to the SNS topic."
