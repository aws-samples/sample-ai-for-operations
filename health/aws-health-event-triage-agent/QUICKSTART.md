# Quick Start — AWS Health Event Triage Agent

This guide walks you from a fresh clone to the full deployed system (all 6 CDK stacks,
tests passing, agent importable) in under 30 minutes.

The default deploy in Step 4 gives you the complete, intended architecture — classification,
routing, digest, **and** the AWS DevOps Agent enrichment/incident-gate path. There is no
smaller "baseline" stage to deploy first; every stack below is part of one deployment. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design and phase-by-phase build
history if you want the "why," not just the "how."

---

## Prerequisites

| Tool | Version | How to install |
|------|---------|----------------|
| Python | 3.12+ | [python.org](https://www.python.org/downloads/) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org/) |
| AWS CDK | 2.x | `npm install -g aws-cdk` |
| AWS CLI | 2.x | [aws.amazon.com/cli](https://aws.amazon.com/cli/) |
| Docker | any recent version, daemon running | [docker.com](https://www.docker.com/products/docker-desktop/) — **required at deploy time.** CDK bundles this repo's Python Lambda functions in a Lambda-compatible Docker container; `cdk deploy` fails immediately if the Docker daemon isn't running. |
| AWS credentials | — | `aws configure` or instance profile |

---

## Step 1 — Clone and create venv

```bash
git clone https://github.com/aws-samples/aws-health-event-triage-agent.git
cd aws-health-event-triage-agent
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Step 2 — Run tests

Runs the unit, property, and integration test suites under `tests/` (`make test-unit`
runs the same command):

```bash
pytest tests/ -q
```

---

## Step 3 — Bootstrap CDK (first time only)

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_REGION=eu-west-1   # change to your preferred region

cdk bootstrap aws://$AWS_ACCOUNT_ID/$AWS_REGION
```

---

## Step 4 — Deploy the infrastructure

```bash
cd infra
npm install
cdk deploy --all
```

This deploys all 6 stacks that make up the system:

| Stack | What it creates |
|-------|----------------|
| `HealthTriageCoreStack` | KMS key, DynamoDB tables (session, consolidated events, idempotency, account-context cache, ticket map, audit log, digest watermark), SQS intake + settle queues, SNS topics, S3 event-snapshot bucket, CloudWatch log group, alarms |
| `HealthTriageGuardrailStack` | Amazon Bedrock Guardrail (content filters + PII anonymization + denied topic) |
| `HealthTriageDevOpsAgentStack` | DevOps Agent incident-gate tables (task tokens, counters, active investigations, readiness assessments) and the default AWS DevOps Agent Space |
| `HealthTriageWorkflowStack` | The Step Functions `TriageWorkflow` (classify → urgency → disposition → inventory → notify → audit) and its Lambda functions |
| `HealthTriageLeafFunctionsStack` | The intake Lambda (SQS consumer) and digest Lambda |
| `HealthTriageDigestStack` | The EventBridge Scheduler that triggers the scheduled digest |

Deploy time: roughly 8–12 minutes for all 6 stacks on a first deploy (Docker image builds
for the Python Lambda bundling take the bulk of it).

**Note the stack outputs** — you'll need `KmsKeyArn` and `ClassificationTopicArn` (from
`HealthTriageCoreStack`) and `GuardrailId`/`GuardrailVersion` (from
`HealthTriageGuardrailStack`) for Step 5.

### About the DevOps Agent enrichment path

The deploy above builds the AWS DevOps Agent Lambdas and Step Functions states, but the
investigation gate they enable is **off by default** (`enableDevOpsAgentGate` defaults to
`false`) because it needs a populated `AgentSpaceRegistry` file first — one you create,
mapping your own accounts to Agent Spaces. Deploying without it still gives you the full
classify → route → digest pipeline; you just don't get AWS DevOps Agent enrichment for
deadline-class events yet.

To turn it on once you have a registry file ready:

```bash
cdk deploy --all -c enableDevOpsAgentGate=true
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#enrichment-code-decides-devops-agent-investigates-phase-a)
for what the registry file needs and how the enrichment path works.

A few other context flags shape the deploy — all have sensible defaults and most users
won't need to touch them:

| Flag | Default | Effect |
|---|---|---|
| `-c deployEnvironment=production\|prototype` | `prototype` | Controls CloudWatch log retention (2 weeks vs. 3 months) |
| `-c enrichmentViaDevOpsAgent=true\|false` | `true` | Routes deadline-class events through the DevOps Agent investigation (`true`) or an entity-list-only baseline (`false`). Only matters when `enableDevOpsAgentGate=true` |
| `-c healthAdminAccountId=<12-digit-account-id>` | unset | Grants that account `events:PutEvents` on the central bus, so org-wide Health events can be forwarded into it. Unset by default: the bus deploys and works for same-account use without it, but with **no cross-account policy** — a CDK synth-time warning (`HealthTriage:NoHealthAdminAccountId`) says so. See Step 7 for the full org-wide ingestion setup this flag is part of. |
| `-c lambdaReservedConcurrency=<integer>` | `5` | Caps the Classify Lambda's concurrent executions (the only Lambda that calls Amazon Bedrock), so a large multi-account event fan-out can't exceed your account's Bedrock on-demand requests-per-minute quota. The default of 5 is a conservative starting point, not a measured value — check your actual quota under **Service Quotas → Amazon Bedrock** for the model in `BEDROCK_MODEL_ID` and raise this flag to match once you've requested an increase. Throttled invocations (`Lambda.TooManyRequestsException`) retry automatically (5 attempts, exponential backoff with jitter) before falling through to the audit-and-fail path, so a temporary cap under real load delays an event rather than failing it. |

### 4.1 — Upload the investigation skill and agent instructions (manual, one-time per Agent Space)

`HealthTriageDevOpsAgentStack` provisions the Agent Space itself but does **not** upload
`devops-agent-skill/SKILL.md` or `devops-agent-skill/agents-md/AGENTS-incident-triage.md` to it —
that upload is a manual step today. Automating it via CloudFormation's
`AWS::DevOpsAgent::Asset` resource is a reasonable future improvement to this construct; it
isn't built yet, so do this step by hand for now.

Get the Agent Space ID from `HealthTriageDevOpsAgentStack`'s `DefaultAgentSpaceId` output. Each
file's content must go through `--cli-input-json file://...` rather than an inline `--content`
string — both files contain newlines and Markdown special characters that a shell-quoted inline
JSON string will not survive intact:

```bash
python3 <<'EOF'
import json

def write_request(out_path, agent_space_id, asset_type, name, agent_types, source_path, dest_filename):
    with open(source_path, encoding="utf-8") as f:
        text = f.read()
    request = {
        "agentSpaceId": agent_space_id,
        "assetType": asset_type,
        "metadata": {"name": name, "agent_types": agent_types},
        "content": {"file": {"path": dest_filename, "body": {"text": text}}},
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(request, f)

AGENT_SPACE_ID = "<AGENT_SPACE_ID>"  # from HealthTriageDevOpsAgentStack's DefaultAgentSpaceId output

write_request(
    "/tmp/create-asset-skill.json", AGENT_SPACE_ID, "skill",
    "health-event-impact-assessment", ["INCIDENT_RCA"],
    "devops-agent-skill/SKILL.md", "SKILL.md",
)
write_request(
    "/tmp/create-asset-agents-md.json", AGENT_SPACE_ID, "agents_md",
    "incident-triage-instructions", ["INCIDENT_TRIAGE"],
    "devops-agent-skill/agents-md/AGENTS-incident-triage.md", "AGENTS.md",
)
EOF

aws devops-agent create-asset --cli-input-json file:///tmp/create-asset-skill.json --region <REGION>
aws devops-agent create-asset --cli-input-json file:///tmp/create-asset-agents-md.json --region <REGION>
rm /tmp/create-asset-skill.json /tmp/create-asset-agents-md.json
```

The `agent_types` values above (`INCIDENT_RCA` for the skill, `INCIDENT_TRIAGE` for the
`AGENTS.md`) match what each file's own header already documents — check `SKILL.md`'s frontmatter
and `AGENTS-incident-triage.md`'s title if you rename or fork either file, so the metadata stays
in sync with the file. Verify with `aws devops-agent list-assets --agent-space-id <AGENT_SPACE_ID>
--region <REGION>` — check for a pre-existing asset with the same `path` before re-running this if
the space isn't brand new, since `create-asset` does not deduplicate against an existing asset for
you.

---

## Step 5 — Configure environment variables (for local/CLI use only)

**This step is not required for the deployed system to work.** The Lambda functions Step
Functions actually invokes already have `SNS_TOPIC_ARN`, `KMS_KEY_ARN`, and every table/secret
name wired onto their environment automatically by CDK at deploy time (see
`infra/lib/triage-workflow.ts`) — nothing you do here changes that. This step only matters if
you want to run `src/` code directly (a local script, a REPL, or manual local testing) outside
the deployed Lambdas, since that code path reads from your shell's environment instead.

Create a `.env` file (not committed) from the template:

```bash
cp .env.example .env
# Edit .env with the values from the CDK stack outputs
```

The stack output names don't match the env var names 1:1 — map them like this:

| Stack output | From stack | Env var |
|---|---|---|
| `ClassificationTopicArn` | `HealthTriageCoreStack` | `SNS_TOPIC_ARN` |
| `GuardrailId` | `HealthTriageGuardrailStack` | `GUARDRAIL_ID` |
| `GuardrailVersion` | `HealthTriageGuardrailStack` | `GUARDRAIL_VERSION` |
| `KmsKeyArn` | `HealthTriageCoreStack` | `KMS_KEY_ARN` |

**`.env` is not loaded automatically — `src/config.py` reads only real process environment
variables (`os.environ`), and nothing in this codebase parses `.env` for you.** Writing values
into the file does nothing on its own; you must load it into your shell:

```bash
set -a
source .env
set +a
```

(`set -a` makes every variable `source .env` sets get exported to the environment, not just
set as a shell variable — plain `source .env` alone is not enough.) Verify it worked:

```bash
python3 -c "import os; print(os.environ.get('SNS_TOPIC_ARN'))"
# should print the real ARN, not an empty string
```

Or skip `.env` entirely and export manually in the same shell you'll run Python from:

```bash
export BEDROCK_MODEL_ID="eu.anthropic.claude-sonnet-5"
export AWS_REGION="eu-west-1"
export SNS_TOPIC_ARN="<ClassificationTopicArn from HealthTriageCoreStack output>"
export GUARDRAIL_ID="<GuardrailId from HealthTriageGuardrailStack output>"
export SESSION_TABLE_NAME="health-triage-sessions"
```

---

## Step 6 — Send a test event (optional, but recommended)

`aws.health` is a reserved EventBridge source — `PutEvents` under it returns
`NotAuthorizedForSourceException` for any caller that isn't AWS itself, so you can't simulate
a real Health event via EventBridge directly. Send a realistic event body straight to the
intake queue instead — this is the same entry point the org-wide EventBridge intake rule
ultimately feeds into.

Get the intake queue URL and the state machine ARN from your stack outputs, then:

```bash
cat > /tmp/test-health-event.json << 'EOF'
{
  "eventArn": "arn:aws:health:eu-west-1::event/EKS/AWS_EKS_FARGATE_POD_EVICTIONS/AWS_EKS_FARGATE_MAINTENANCE_TEST_2026",
  "eventTypeCode": "AWS_EKS_FARGATE_POD_EVICTIONS",
  "eventTypeCategory": "scheduledChange",
  "service": "EKS",
  "region": "eu-west-1",
  "statusCode": "upcoming",
  "eventScopeCode": "ACCOUNT_SPECIFIC",
  "startTime": "2026-10-05T00:00:00Z",
  "endTime": "",
  "lastUpdatedTime": "2026-09-29T12:00:00Z",
  "eventDescription": "AWS will perform operating system security patching on Amazon EKS Fargate pods in profile fp-default between October 5-12, 2026. Pods will be gracefully terminated and restarted.",
  "affectedEntities": [
    {
      "entityValue": "arn:aws:eks:<region>:<account-id>:fargateprofile/prod-cluster/fp-default",
      "entityArn": "arn:aws:eks:<region>:<account-id>:fargateprofile/prod-cluster/fp-default",
      "entityStatus": "UNKNOWN",
      "lastUpdatedTime": "",
      "tags": {}
    }
  ],
  "affectedAccounts": ["<account-id>"],
  "pagesReceived": [1],
  "totalPages": 1
}
EOF

aws sqs send-message \
  --queue-url <IntakeQueueUrl from HealthTriageCoreStack output> \
  --message-body file:///tmp/test-health-event.json
```

The intake Lambda enqueues a delayed settle message (60s default, `INTAKE_SETTLE_SECONDS`)
before starting the workflow, so wait ~60–90 seconds, then check for the resulting execution:

```bash
aws stepfunctions list-executions \
  --state-machine-arn <StateMachineArn from HealthTriageWorkflowStack output> \
  --max-items 3
```

A `SUCCEEDED` execution confirms the deployed pipeline actually works end-to-end, not just
that `cdk deploy` didn't error.

---

## Step 7 — Org-wide ingestion across your AWS Organization (optional)

Everything above deploys and works for a **single account** — the `HealthTriageCoreStack`
central bus accepts same-account Health events with no further setup. This step is only
needed if you want to ingest AWS Health events from **every account in an AWS
Organization** into that one central bus. Skip it if you're evaluating this agent against
a single account.

### Prerequisites

- **AWS Health organizational view must already be enabled** in your AWS Organization,
  from the management account or a registered delegated administrator — see
  [Enabling organizational view](https://docs.aws.amazon.com/health/latest/ug/enable-organizational-view.html).
  This requires a Business, Enterprise On-Ramp, Enterprise, or Unified Operations Support
  plan. This repository does not enable this for you.
- The account with organizational view enabled (the "Health admin account" below) can be
  the management account itself, a delegated administrator, or — for a single-account
  evaluation with no real Organization — this same agent account, exercising the
  mechanics without genuine cross-account forwarding.

### 7.1 — Grant the Health admin account permission on the central bus

Redeploy `HealthTriageCoreStack` with the Health admin account's 12-digit ID:

```bash
cd infra
cdk deploy HealthTriageCoreStack --exclusively -c enableDevOpsAgentGate=true \
  -c healthAdminAccountId=<health-admin-account-id>
```

(Add any other context flags you're already using, e.g. `enableDevOpsAgentGate=true`, so
this redeploy doesn't accidentally revert them — `cdk deploy` only applies the flags you
pass on each invocation, it doesn't remember previous ones.)

Verify the policy attached:

```bash
aws events describe-event-bus --name health-triage-central --query Policy --output text
# should show a statement with your health admin account as Principal
```

### 7.2 — One-time StackSet prerequisites (per AWS account, if not already done)

CloudFormation StackSets with self-managed permissions need two IAM roles that don't
exist by default. If this is the first StackSet you've ever deployed with self-managed
permissions in these accounts, create them using AWS's own templates — deploy the
administration role in the account you'll run `create-stack-set` from (the agent account,
in the common case where it's also the Health admin account), and the execution role in
every account that will receive stack instances:

```bash
# In the "administrator" account (where you run create-stack-set)
aws cloudformation deploy \
  --template-file <(curl -s https://s3.amazonaws.com/cloudformation-stackset-sample-templates-us-east-1/AWSCloudFormationStackSetAdministrationRole.yml) \
  --stack-name StackSetAdministrationRole \
  --capabilities CAPABILITY_NAMED_IAM

# In each "target" account (the Health admin account, if different)
aws cloudformation deploy \
  --template-file <(curl -s https://s3.amazonaws.com/cloudformation-stackset-sample-templates-us-east-1/AWSCloudFormationStackSetExecutionRole.yml) \
  --stack-name StackSetExecutionRole \
  --parameter-overrides AdministratorAccountId=<administrator-account-id> \
  --capabilities CAPABILITY_NAMED_IAM
```

See [Grant self-managed permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html)
for the full explanation. If your organization uses AWS Organizations-managed StackSets
instead (`--permission-model SERVICE_MANAGED`), skip this and see
[Activate trusted access](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-activate-trusted-access.html)
instead.

### 7.3 — Deploy StackSet A (`infra/stacksets/health-forwarding.yaml`)

This template deploys, in each target Region, an EventBridge rule that forwards
`aws.health` events to your central bus, plus the IAM role that rule assumes to do it.
Run this once, from the Health admin account:

```bash
aws cloudformation create-stack-set \
  --stack-set-name health-triage-forwarding \
  --template-body file://infra/stacksets/health-forwarding.yaml \
  --parameters \
      ParameterKey=CentralBusArn,ParameterValue=<CentralBusArn from HealthTriageCoreStack output> \
      ParameterKey=AgentAccountId,ParameterValue=<agent-account-id> \
  --capabilities CAPABILITY_NAMED_IAM \
  --permission-model SELF_MANAGED

aws cloudformation create-stack-instances \
  --stack-set-name health-triage-forwarding \
  --accounts <health-admin-account-id> \
  --regions us-east-1 <your-other-enabled-regions...>
```

**Deploy to every Region you have Health events enabled in — this is required even for a
single-account setup, not just multi-account.** AWS Health delivers events per-Region;
there is no single-Region shortcut that covers everything. `us-east-1` specifically is
**mandatory** regardless of your other Regions, because global/`PUBLIC`-scope events (e.g.
IAM-related Health events) are only ever delivered there — see
[Creating EventBridge rules for AWS Region coverage](https://docs.aws.amazon.com/health/latest/ug/choosing-a-region.html).
(That page also documents a `us-west-2` "simplified integration" single-rule shortcut —
do not use it here: it explicitly excludes `PUBLIC`-scope events, which this agent is
designed to handle.)

Verify:

```bash
aws cloudformation list-stack-instances --stack-set-name health-triage-forwarding \
  --query 'Summaries[].{Region:Region,Status:Status}' --output table
# every Region should show CURRENT
```

### 7.4 — Connect member accounts to the AWS DevOps Agent Agent Space (optional, for enrichment)

Step 7.1–7.3 above get AWS Health events flowing from every account into this agent's central
bus — that's the classify/route/digest pipeline's own multi-account story, and it needs nothing
from this section. This section is a **separate** multi-account concern: making the AWS DevOps
Agent investigation gate (`-c enableDevOpsAgentGate=true`) able to see resources in accounts
*other than* the one `HealthTriageDevOpsAgentStack` deploys into.

**Skip this if you're only running the investigation gate against one account** — the stack's
default `DefaultAgentSpace` already monitors its own account with no further setup.

**Why this can't be a CDK stack in this repo.** An Agent Space has one "primary/monitor" account
(where the space and its monitoring role live — what this repo's CDK builds) and, optionally, any
number of "secondary/source" accounts it can also see. Making a second account visible means
creating an IAM role **inside that account** that trusts the Agent Space's service principal
directly — this repo's CDK only ever deploys into the one account you target with `cdk deploy`,
so it structurally cannot reach into a different account's IAM without a StackSet (which does not
exist for this yet — see the "Known gap" note below). This is documented, supported AWS
functionality, not something specific to this repo: see [Connecting multiple AWS
Accounts](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-integrations-and-knowledge-connecting-multiple-aws-accounts.html)
and the [CLI onboarding
guide](https://docs.aws.amazon.com/devopsagent/latest/userguide/getting-started-with-aws-devops-agent-cli-onboarding-guide.html)'s
step 4, which this section follows.

Also worth knowing up front, from the master design (`design.md` §7's rejected-alternatives log):
the recommended production topology is **one Agent Space per business unit, in a dedicated
operations-tooling account** — not one space per member account, and not a space living in your
AWS Health delegated-admin account (that account already holds one org-wide read scope; adding an
Agent Space's own broad access there is a second one, for no benefit). Decide your account
topology against that guidance before connecting accounts below.

**Step 1 — get the primary account's Agent Space ID and region** from
`HealthTriageDevOpsAgentStack`'s `DefaultAgentSpaceId` output.

**Step 2 — in each member account, create the cross-account role** that the Agent Space will
assume. This role lives in the member account, not in the account you deployed
`HealthTriageDevOpsAgentStack` into:

```bash
# Run this against the MEMBER account's credentials, not the primary account's.
cat > /tmp/devops-agent-source-trust-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "aidevops.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "aws:SourceAccount": "<PRIMARY_ACCOUNT_ID>" },
        "ArnLike": { "aws:SourceArn": "arn:aws:aidevops:<REGION>:<PRIMARY_ACCOUNT_ID>:agentspace/<AGENT_SPACE_ID>" }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name DevOpsAgentCrossAccountRole \
  --assume-role-policy-document file:///tmp/devops-agent-source-trust-policy.json

aws iam attach-role-policy \
  --role-name DevOpsAgentCrossAccountRole \
  --policy-arn arn:aws:iam::aws:policy/AIDevOpsAgentAccessPolicy

aws iam get-role --role-name DevOpsAgentCrossAccountRole --query 'Role.Arn' --output text
```

Note the trust policy's `aws:SourceArn` is scoped to this **one specific Agent Space**
(`agentspace/<AGENT_SPACE_ID>`), not the wildcard `agentspace/*` this repo's own primary-account
role uses — a secondary account's role should only ever be assumable by the one space you're
connecting it to.

**Step 3 — grant `iam:PassRole` in the primary account**, if the identity you'll run Step 4 as
doesn't already have it. AWS DevOps Agent checks this when you connect a secondary account and
fails with a confusing `AccessDeniedException` naming `iam:PassRole` if it's missing, even for a
caller with full `aidevops:*` access otherwise:

```bash
cat > /tmp/pass-role-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<PRIMARY_ACCOUNT_ID>:role/*",
      "Condition": { "StringEquals": { "iam:PassedToService": "aidevops.amazonaws.com" } }
    }
  ]
}
EOF
# Attach this to whatever identity policy you'll run Step 4 as, in the primary account.
```

**Step 4 — back in the primary account, associate the member account as a `source`**:

```bash
aws devops-agent associate-service \
  --agent-space-id <AGENT_SPACE_ID> \
  --service-id aws \
  --configuration '{
    "sourceAws": {
      "accountId": "<MEMBER_ACCOUNT_ID>",
      "accountType": "source",
      "assumableRoleArn": "arn:aws:iam::<MEMBER_ACCOUNT_ID>:role/DevOpsAgentCrossAccountRole"
    }
  }' \
  --region <REGION>
```

Repeat Steps 2–4 for every member account this BU's space should investigate. Verify with `aws
devops-agent list-associations --agent-space-id <AGENT_SPACE_ID> --region <REGION>`.

**Step 5 — add one `ACCOUNT` (or `OU`) rule per connected member account** to
`config/agent_space_registry.json`, all pointing at the same `agentSpaceId`/`webhookUrl`/
`webhookSecretArn` from `HealthTriageDevOpsAgentStack`'s outputs — `resolve_agent_spaces_by_account()`
(`src/devops_agent/registry.py`) groups accounts by `agentSpaceId`, so several registry rules
naming the same space correctly collapse into one investigation per space, not one per account.

**If you have more than one business unit**, repeat this whole section per BU: a separate
operations-tooling account, a separate `cdk deploy` of `HealthTriageDevOpsAgentStack` (or a
separate `DevOpsAgentSpace` construct instance), a separate set of registry rules pointing at
that BU's space.

**Known gap, tracked for a future release:** this repo has no CDK/StackSet automation for Step 2
(the member-account role) — unlike the Health-forwarding side (`infra/stacksets/health-forwarding.yaml`),
which does deploy via StackSet to every member account. Automating the member-account role the
same way is a reasonable follow-up; it hasn't been built yet.

---

## What's built vs. what's planned

Everything in Step 4 above — ingestion, classification, routing, digest, and AWS DevOps
Agent enrichment — is built and deployed by that one command. Only PR-based remediation
and formal evaluation/release-readiness work remain planned. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#phase-status) for the full phase-by-phase
status table.

---

## Troubleshooting

**`ImportError: No module named 'strands'`**
→ Activate the venv: `source .venv/bin/activate`

**`cdk deploy` fails with a Docker-related error** (e.g. `Cannot connect to the Docker
daemon`, or bundling hangs/fails silently)
→ Start Docker Desktop (or your Docker daemon) before running `cdk deploy`. This repo's
Python Lambda functions are bundled in a Lambda-compatible Docker container at deploy
time — there is no way to skip this for the CDK stacks in Step 4.

**`cdk deploy --all` fails with `Cannot delete/update export ... as it is in use by
<OtherStack>`, or a stack seems stuck mid-update**
→ This means one of the 6 stacks is being deployed or torn down out of order relative to
its cross-stack dependencies. `cdk deploy --all` normally handles ordering for you; if
you're deploying or deleting stacks individually by name, delete in this order:
`HealthTriageDigestStack` → `HealthTriageLeafFunctionsStack` → `HealthTriageWorkflowStack`
→ `HealthTriageDevOpsAgentStack` → `HealthTriageGuardrailStack` →
`HealthTriageCoreStack` (reverse of deploy order).

**`create-stack-set` fails, or stack instances fail with an `AssumeRole` / role-not-found
error** (Step 7)
→ The two IAM prerequisite roles (`AWSCloudFormationStackSetAdministrationRole`,
`AWSCloudFormationStackSetExecutionRole`) don't exist yet in one of the accounts
involved. Run Step 7.2 first — StackSets with self-managed permissions don't create these
roles for you.

**CDK bootstrap fails with `AccessDenied`**
→ Bootstrap creates the `CDKToolkit` stack (an S3 asset bucket, an ECR repo, and
IAM deployment roles) and by default provisions those roles with `AdministratorAccess`
— see [CDK bootstrapping](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html).
For the one-time bootstrap step only, use a role with `AdministratorAccess` or
equivalent broad access; do not add `IAM:*` or other service-wide wildcards to a
role used for anything beyond bootstrap. For ongoing deployments, scope the
CloudFormation execution role with `--cloudformation-execution-policies` to your
own least-privilege managed policy instead of the default admin role — see
[Customize bootstrapping](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-customizing.html)
and [Permissions boundaries for the CDK](https://docs.aws.amazon.com/cdk/v2/guide/customize-permissions-boundaries.html).

**Tests fail with `botocore.exceptions.NoCredentialsError`**
→ The unit tests mock all AWS calls. If this error appears, a mock is missing — check
the `@patch` decorators in the failing test file.

**Amazon Bedrock Guardrail `AccessDenied` on deploy**
→ The IAM principal deploying CloudFormation needs `bedrock:CreateGuardrail` and
`bedrock:CreateGuardrailVersion`. Add these to your deployment role.
