#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# Pause or resume the daily schedule without a redeploy (used by the missed-run alarm test,
# tests/operational/README.md §3). UpdateSchedule replaces the whole definition, so this reads
# the current schedule and writes it back with only State changed.
# A later `scripts/deploy.sh` also resets the state to ENABLED.
set -euo pipefail

STATE="${1:?usage: scripts/set-schedule-state.sh ENABLED|DISABLED}"
[[ "$STATE" == "ENABLED" || "$STATE" == "DISABLED" ]] || { echo "state must be ENABLED or DISABLED"; exit 1; }
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
: "${REGION:?Set AWS_REGION}"

name="$(aws scheduler list-schedules --region "$REGION" --no-cli-pager \
  --query "Schedules[?starts_with(Name,'NetworkRoutingDriftChecker-DailySchedule')].Name | [0]" --output text)"
[[ -n "$name" && "$name" != "None" ]] || { echo "schedule not found in $REGION"; exit 1; }

current="$(aws scheduler get-schedule --region "$REGION" --no-cli-pager --name "$name" --output json)"
input="$(python3 -c '
import json, sys
s = json.load(sys.stdin)
keep = ["Name", "GroupName", "ScheduleExpression", "ScheduleExpressionTimezone", "FlexibleTimeWindow",
        "Target", "Description", "StartDate", "EndDate", "KmsKeyArn", "ActionAfterCompletion"]
out = {k: s[k] for k in keep if k in s and s[k] is not None}
for k in ("StartDate", "EndDate"):
    if k in out:
        out[k] = str(out[k])
out["State"] = sys.argv[1]
print(json.dumps(out))
' "$STATE" <<<"$current")"

aws scheduler update-schedule --region "$REGION" --no-cli-pager --cli-input-json "$input" >/dev/null
echo "$name: $(aws scheduler get-schedule --region "$REGION" --no-cli-pager --name "$name" --query State --output text)"
