#!/usr/bin/env bash
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# One-command deploy (requirements §14.5). Uses your current AWS credentials and Region
# (AWS_PROFILE / AWS_REGION). Reads settings from .deploy.env (see deploy.env.example).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${DEPLOY_ENV_FILE:-$ROOT/.deploy.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi
: "${SCHEDULE_TIMEZONE:?Set SCHEDULE_TIMEZONE (e.g. Europe/Berlin) in .deploy.env or the environment}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
  echo "Creating .venv with $PYTHON_BIN"
  "$PYTHON_BIN" -m venv "$ROOT/.venv"
fi
"$ROOT/.venv/bin/pip" install --quiet -r "$ROOT/requirements.txt"
export PYTHON="$ROOT/.venv/bin/python"   # used by the CDK local bundler

cd "$ROOT/infra"
npm ci --no-audit --no-fund --silent

ACCOUNT="$(aws sts get-caller-identity --query Account --output text --no-cli-pager)"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}"
: "${REGION:?Set AWS_REGION}"
echo "Deploying to account $ACCOUNT in $REGION"

if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" --no-cli-pager >/dev/null 2>&1; then
  echo "Bootstrapping CDK in $ACCOUNT/$REGION"
  npx cdk bootstrap "aws://$ACCOUNT/$REGION"
fi

params=(--parameters "ScheduleTimezone=$SCHEDULE_TIMEZONE")
add() { [[ -n "${2:-}" ]] && params+=(--parameters "$1=$2"); return 0; }
add NotificationEmail "${NOTIFICATION_EMAIL:-}"
add ScheduleExpression "${SCHEDULE_EXPRESSION:-}"
add RegionAllowlist "${REGION_ALLOWLIST:-}"
add RegionExcludeList "${REGION_EXCLUDE_LIST:-}"
add EnvironmentTagKey "${ENVIRONMENT_TAG_KEY:-}"
add ProductionTagValues "${PRODUCTION_TAG_VALUES:-}"
add LimitThresholdPercent "${LIMIT_THRESHOLD_PERCENT:-}"
add LogRetentionDays "${LOG_RETENTION_DAYS:-}"

# ── DevOps Agent hand-off (requirements §11.1, design D§3.3/D§3.3a) ─────────
HANDOFF="${ENABLE_DEVOPS_AGENT_HANDOFF:-false}"
AGENT_ACCOUNT="${DEVOPS_AGENT_ACCOUNT_ID:-}"
CROSS_ACCOUNT=false
if [[ "$HANDOFF" == "true" ]]; then
  : "${DEVOPS_AGENT_WEBHOOK_URL:?ENABLE_DEVOPS_AGENT_HANDOFF=true requires DEVOPS_AGENT_WEBHOOK_URL}"
  : "${WEBHOOK_SECRET_PARAMETER_NAME:?ENABLE_DEVOPS_AGENT_HANDOFF=true requires WEBHOOK_SECRET_PARAMETER_NAME}"
  : "${DEVOPS_AGENT_SPACE_ID:?ENABLE_DEVOPS_AGENT_HANDOFF=true requires DEVOPS_AGENT_SPACE_ID}"
  # Events land in the Agent Space's Region; a different Region means every investigation times out.
  url_region="$(printf '%s' "$DEVOPS_AGENT_WEBHOOK_URL" | sed -nE 's#^https://event-ai\.([a-z0-9-]+)\.api\.aws/webhook/generic/.+$#\1#p')"
  if [[ "$url_region" != "$REGION" ]]; then
    echo "ERROR: the webhook URL's Region (${url_region:-unparseable}) must equal the deploy Region ($REGION)." >&2
    exit 1
  fi
  if ! aws ssm describe-parameters --region "$REGION" --no-cli-pager --output text \
      --parameter-filters "Key=Name,Values=$WEBHOOK_SECRET_PARAMETER_NAME" --query 'Parameters[0].Type' \
      | grep -qx SecureString; then
    echo "ERROR: $WEBHOOK_SECRET_PARAMETER_NAME is not an SSM SecureString parameter in $ACCOUNT/$REGION." >&2
    exit 1
  fi
  params+=(--parameters "EnableDevOpsAgentHandoff=true"
    --parameters "DevOpsAgentWebhookUrl=$DEVOPS_AGENT_WEBHOOK_URL"
    --parameters "WebhookSecretParameterName=$WEBHOOK_SECRET_PARAMETER_NAME"
    --parameters "DevOpsAgentSpaceId=$DEVOPS_AGENT_SPACE_ID")
  add DevOpsAgentAccountId "$AGENT_ACCOUNT"
  add MaxFindingsPerInvestigation "${MAX_FINDINGS_PER_INVESTIGATION:-}"
  add InvestigationConcurrency "${INVESTIGATION_CONCURRENCY:-}"
  add InvestigationTimeoutSeconds "${INVESTIGATION_TIMEOUT_SECONDS:-}"
  add InvestigationHeartbeatSeconds "${INVESTIGATION_HEARTBEAT_SECONDS:-${INVESTIGATION_TIMEOUT_SECONDS:-}}"
  if [[ -n "$AGENT_ACCOUNT" && "$AGENT_ACCOUNT" != "$ACCOUNT" ]]; then
    CROSS_ACCOUNT=true
    : "${DEVOPS_AGENT_PROFILE:?A cross-account hand-off requires DEVOPS_AGENT_PROFILE (credentials for $AGENT_ACCOUNT)}"
    linked="$(AWS_PROFILE="$DEVOPS_AGENT_PROFILE" aws sts get-caller-identity --query Account --output text --no-cli-pager)"
    if [[ "$linked" != "$AGENT_ACCOUNT" ]]; then
      echo "ERROR: DEVOPS_AGENT_PROFILE points at account $linked, expected $AGENT_ACCOUNT." >&2
      exit 1
    fi
  fi
fi

# broadening = CDK asks before creating or widening IAM permissions (interactive default).
# Non-interactive runs (CI, agents) set CDK_REQUIRE_APPROVAL=never after reviewing the diff.
# --no-previous-parameters: every deploy is defined by .deploy.env plus the template defaults.
# Without it, CDK keeps an unset parameter's previous value, so a changed default never reaches
# an existing stack (found live 2026-10-15: the investigation timeout stayed at 900 s).
npx cdk deploy NetworkRoutingDriftChecker --region "$REGION" --no-previous-parameters \
  --require-approval "${CDK_REQUIRE_APPROVAL:-broadening}" "${params[@]}"

if [[ "$CROSS_ACCOUNT" == "true" ]]; then
  output() {
    aws cloudformation describe-stacks --stack-name NetworkRoutingDriftChecker --region "$REGION" --no-cli-pager \
      --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text
  }
  CALLBACK_ARN="$(output CallbackFunctionArn)"
  CALLBACK_ROLE_ARN="$(output CallbackRoleArn)"
  echo "Deploying the DevOps Agent link stack to account $AGENT_ACCOUNT in $REGION"
  if ! AWS_PROFILE="$DEVOPS_AGENT_PROFILE" aws cloudformation describe-stacks --stack-name CDKToolkit \
      --region "$REGION" --no-cli-pager >/dev/null 2>&1; then
    echo "ERROR: account $AGENT_ACCOUNT is not CDK-bootstrapped in $REGION (npx cdk bootstrap aws://$AGENT_ACCOUNT/$REGION)." >&2
    exit 1
  fi
  AWS_PROFILE="$DEVOPS_AGENT_PROFILE" npx cdk deploy NetworkRoutingDriftChecker-DevOpsAgentLink --region "$REGION" \
    --no-previous-parameters --require-approval "${CDK_REQUIRE_APPROVAL:-broadening}" -c skipBundling=true \
    --parameters "CheckerAccountId=$ACCOUNT" --parameters "CallbackFunctionArn=$CALLBACK_ARN" \
    --parameters "CallbackRoleArn=$CALLBACK_ROLE_ARN" --parameters "DevOpsAgentSpaceId=$DEVOPS_AGENT_SPACE_ID"

  # Probe, fail-closed: both sides of the link must exist and point at each other.
  READER="nrdc-journal-reader-$ACCOUNT-$REGION"
  FORWARDER="nrdc-event-forwarder-$ACCOUNT-$REGION"
  probe_failed=false
  for role in "$READER" "$FORWARDER"; do
    if ! AWS_PROFILE="$DEVOPS_AGENT_PROFILE" aws iam get-role --role-name "$role" --no-cli-pager >/dev/null 2>&1; then
      echo "PROBE: role $role is missing in account $AGENT_ACCOUNT." >&2
      probe_failed=true
    fi
  done
  trust="$(AWS_PROFILE="$DEVOPS_AGENT_PROFILE" aws iam get-role --role-name "$READER" --no-cli-pager \
    --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null || true)"
  if [[ "$trust" != *"$CALLBACK_ROLE_ARN"* ]]; then
    echo "PROBE: $READER does not trust $CALLBACK_ROLE_ARN." >&2
    probe_failed=true
  fi
  policy="$(aws lambda get-policy --function-name "$CALLBACK_ARN" --region "$REGION" --no-cli-pager \
    --query Policy --output text 2>/dev/null || true)"
  if [[ "$policy" != *"$AGENT_ACCOUNT"* ]]; then
    echo "PROBE: the callback's resource policy does not allow account $AGENT_ACCOUNT." >&2
    probe_failed=true
  fi
  decision="$(aws iam simulate-principal-policy --policy-source-arn "$CALLBACK_ROLE_ARN" --no-cli-pager \
    --action-names sts:AssumeRole --resource-arns "arn:aws:iam::$AGENT_ACCOUNT:role/$READER" \
    --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null || echo unknown)"
  if [[ "$decision" != "allowed" ]]; then
    echo "PROBE: the callback role may not sts:AssumeRole $READER (simulation: $decision)." >&2
    probe_failed=true
  fi
  if [[ "$probe_failed" == "true" ]]; then
    echo "ERROR: the cross-account hand-off is not complete. Fix the items above and re-run, or disable the" >&2
    echo "       hand-off (ENABLE_DEVOPS_AGENT_HANDOFF=false) so investigations don't time out silently." >&2
    exit 1
  fi
  echo "Cross-account link verified: events from $AGENT_ACCOUNT can reach the callback, and it can read the journal."
fi
echo "Deployed. Confirm the SNS e-mail subscription if you set NOTIFICATION_EMAIL, then run scripts/smoke-test.sh."
