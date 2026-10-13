# Security

## Overview

The AWS Health Event Triage Agent is a serverless AI-powered system that processes AWS Health events across multi-account organizations. This document provides the security threat model, data classification, and security controls implemented to protect organizational infrastructure visibility and incident response processes.

## Data Classification

| Data Type | Classification | Sensitivity | Retention |
|-----------|---------------|-------------|-----------|
| AWS Health Events | Confidential | Medium | 400 days (configurable) |
| Event Classifications | Internal | Medium | Same as events |
| Agent Space Registry | Confidential | High | Configuration-managed |
| Webhook Secrets | Secret | Critical | Manual rotation (customer-managed) — no automated rotation schedule is configured by this codebase |
| Audit Logs | Internal | Medium | 90 days minimum |
| Investigation Results | Confidential | Medium | Same as events |

## Architecture Security Controls

### Encryption at Rest
- **DynamoDB**: All tables encrypted with customer-managed KMS keys, point-in-time recovery enabled
- **S3**: Event snapshots encrypted with SSE-KMS, versioning enabled, public access blocked
- **SQS**: All queues encrypted with customer-managed KMS keys
- **SNS**: All topics encrypted with customer-managed KMS keys
- **Secrets Manager**: Webhook credentials encrypted with customer-managed KMS keys

### Encryption in Transit
- **HTTPS Only**: All external communications use TLS 1.2+ (`_validate_https()` rejects any
  non-`https://` webhook/secret URL before use in `src/sinks/` and `src/devops_agent/trigger.py`)
- **Outbound webhook signing**: this agent signs its own **outbound** calls to the AWS DevOps
  Agent eventChannel webhook with HMAC-SHA256 (`src/devops_agent/trigger.py`'s `sign_webhook`).
  There is no inbound webhook — investigation completion arrives via an EventBridge rule
  (`aws.aidevops` source, `infra/bin/app.ts`'s `AidevopsCallbackRule`) delivered to
  `src/devops_agent/callback_handler.py`, so there is no inbound signature to validate and no
  rate limiting on an inbound endpoint (none exists).

### Access Control
- **Least Privilege**: IAM roles grant minimum necessary permissions
- **Read-Only Default**: No customer resource mutation permissions by default
- **Resource Scoping**: Permissions limited to specific ARNs, no `Resource: "*"` for write operations
- **Cross-Account Protection**: Agent Space registry controls investigation access per account

## Threat Model Summary

Based on STRIDE analysis (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege):

### Risk Summary by Severity

Statuses below reflect each control actually present in `src/`/`infra/` as of this
revision. Every PARTIALLY MITIGATED entry below states its specific "not implemented"
gap inline. Most gaps are disclosed, accepted trade-offs for a sample/prototype, not
oversights.

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 1 | 🟡 PARTIALLY MITIGATED (secret rotation not configured) |
| HIGH | 4 | 🟡 1 MITIGATED, 3 PARTIALLY MITIGATED |
| MEDIUM | 8 | 🟡 1 MITIGATED, 7 PARTIALLY MITIGATED |
| LOW | 2 | 🟡 1 MITIGATED, 1 PARTIALLY MITIGATED |

**Security Gate: PASS** ✅ (0 *unmitigated* HIGH severity threats — every HIGH-severity
threat retains at least one real, working control; "partially" means a named sub-control
is missing, not that the threat is undefended)

### Key Threat Categories

#### SPOOFING
- **S1: Malicious AWS Health Event Injection** (MEDIUM) - **PARTIALLY MITIGATED**
  - EventBridge source filtering (`aws.health` only) and the central bus's resource policy,
    scoped to the configured Health admin account (`infra/lib/core-stack.ts`'s
    `AllowHealthAdminAccount` statement), are the real controls in place today.
  - There is **no application-level event signature validation** in the intake Lambda — the
    code relies entirely on the EventBridge source-account restriction above. A caller with
    `events:PutEvents` on the central bus within the allowed account is not currently
    distinguished from a genuine AWS Health event.

- **S2: AWS DevOps Agent Webhook Spoofing** (HIGH) - **NOT APPLICABLE AS DESCRIBED — SEE CORRECTED MODEL**
  - This agent has no inbound webhook to spoof. It calls the AWS DevOps Agent eventChannel
    webhook **outbound** (HMAC-SHA256-signed via `src/devops_agent/trigger.py`'s
    `sign_webhook`), and investigation completion is delivered back **inbound** via a native
    EventBridge rule (`aws.aidevops` source, same-account central bus — see
    `infra/bin/app.ts`'s `AidevopsCallbackRule`), not a webhook this agent exposes. The
    relevant spoofing surface is therefore "can an untrusted source put a fake
    `aws.aidevops` event on the central bus", which is bounded by the same EventBridge
    same-account/source-filtering control as S1, not by HMAC or a rate limiter — neither of
    which exists on an inbound path because there is no inbound endpoint.

#### TAMPERING
- **T1: Event Classification Manipulation** (HIGH) - **PARTIALLY MITIGATED**
  - Structured prompts resist instruction injection
  - Amazon Bedrock Guardrails content filtering
  - Output schema validation with UNCLASSIFIED fallback
  - *Note: 85% reliability from evaluation; 2 minor findings addressed via safety nets*

- **T2: Investigation Result Tampering** (MEDIUM) - **PARTIALLY MITIGATED**
  - The outbound trigger call is HTTPS + HMAC-signed (see S2, above). The **inbound** result
    — the investigation outcome delivered via the `aws.aidevops` EventBridge rule and read
    from the AWS DevOps Agent journal (`callback_handler.py`) — carries no signature of its
    own; it is trusted based on the same-account EventBridge delivery path.
  - S3 event snapshots (`EventSnapshotBucket`) are versioned and KMS-encrypted, which
    provides tamper-evidence (a prior version is recoverable) but the bucket is not
    configured with S3 Object Lock, so this is not true immutability.

- **T3: Configuration Tampering** (MEDIUM) - **PARTIALLY MITIGATED**
  - Routing rules, disposition overrides, and the Agent Space registry are JSON files
    bundled into the Lambda package at build time — changing them requires the same
    access needed to redeploy, not a separate configuration-write permission
  - These are not DynamoDB resources (no config data lives in DynamoDB), and no deployment
    pipeline approval gate exists in this repository

#### INFORMATION DISCLOSURE  
- **ID1: Cross-Account Event Information Leakage** (HIGH) - **MITIGATED**
  - Account-scoped Agent Space mappings
  - Team routing based on resource ownership
  - No cross-account resource access in default policies

- **ID2: Webhook Secret Exposure** (CRITICAL) - **MITIGATED**
  - AWS Secrets Manager with KMS encryption; secrets are never in environment variables
  - Runtime secret retrieval with IAM restrictions scoped to specific secret ARNs
  - **No automated rotation is configured** — `infra/lib/core-stack.ts`'s `jiraSecret`/
    `slackSecret`/`teamsSecret` have no `addRotationSchedule`. Rotation, if desired, is a
    customer-configured operational step, not something this codebase enforces on a
    90-day (or any) cadence.
  - `src/sinks/slack_sink.py` and `teams_sink.py` previously logged the full webhook URL on
    an HTTP error via `requests`' `raise_for_status()` message — fixed to log only
    `status_code`/`reason` (see the "no secrets in logs" fix in this same release).

- **ID3: Classification Logic Reverse Engineering** (MEDIUM) - **MITIGATED**
  - The system prompt (`src/prompts/classifier.md`) ships **embedded in the Lambda
    deployment package by default**. `SYSTEM_PROMPT_S3_BUCKET` is an optional override
    (empty by default — `src/config.py`); no CDK stack sets it, so a default deployment
    does not use S3 for the prompt. Externalizing to S3 is available, not automatic.
  - Multiple validation layers (JSON schema validation, UNCLASSIFIED fallback,
    deterministic disposition overrides) remain accurate as shipped.

#### DENIAL OF SERVICE
- **DOS1: EventBridge Message Flooding** (MEDIUM) - **MITIGATED**
  - SQS queue depth alarms (`infra/lib/core-stack.ts`'s `DlqDepthAlarm`/`SettleDlqDepthAlarm`)
  - Reserved concurrency on the Classifier Lambda (default 5, configurable via the
    `lambdaReservedConcurrency` CDK context flag) caps concurrent Bedrock calls under a
    large multi-account fan-out
  - Dead letter queues for recovery (intake and settle queues each have their own DLQ)

- **DOS2: Amazon Bedrock API Throttling** (MEDIUM) - **MITIGATED**
  - Reserved concurrency on the Classifier Lambda bounds concurrent Bedrock calls under
    multi-account fan-out (see DOS1, above)
  - Jittered exponential backoff between the classifier's two invocation attempts
    (`src/classifier/service.py`) — no circuit breaker exists; after both attempts fail,
    the call returns the deterministic `UNCLASSIFIED` fallback rather than tripping a
    breaker for subsequent events
  - UNCLASSIFIED fallback maintains flow

- **DOS3: DynamoDB Throttling** (MEDIUM) - **PARTIALLY MITIGATED**
  - Every table uses on-demand (`PAY_PER_REQUEST`) billing, which scales automatically
    with load — no capacity to exhaust in the way provisioned-mode throttling implies
  - No batch API calls and no custom capacity-monitoring alarm exist in this codebase

#### ELEVATION OF PRIVILEGE
- **EOP1: Lambda Function Role Escalation** (HIGH) - **PARTIALLY MITIGATED**
  - Read-only IAM policies against customer resources by default (no tool in this codebase
    calls a mutating AWS API against a customer account — see `MUTATING_ACTIONS.md`)
  - Resource-level permissions with specific ARNs on every grant this codebase provisions
    (DynamoDB tables, the Guardrail, Secrets Manager secrets, S3 prefixes)
  - **No IAM permission boundary is attached to any role.** `infra/` does not set
    `permissionsBoundary` anywhere — least-privilege here comes entirely from each role's
    own scoped policy statements, not from a boundary that caps what could be added later.

- **EOP2: DevOps Agent Investigation Privilege Escalation** (MEDIUM) - **MITIGATED**
  - Agent Space registry controls access
  - Monthly investigation caps per space
  - Investigation scoped to specific event resources

## AI/ML Security

### Model Security (Amazon Bedrock)
- **Model**: Claude Sonnet 5 (`eu.anthropic.claude-sonnet-5`) via eu-west-1 inference profile
- **Guardrails**: Amazon Bedrock Guardrails enabled for content filtering and PII detection
- **Prompt Injection**: Structured prompts with clear instructions to ignore embedded commands
- **Output Validation**: JSON schema validation against `classification_result_v1.json`
- **Reliability**: 85% accuracy (17/20) from evaluation with prompt injection resistance verified

### Prompt Security
- **Prompt location**: `src/prompts/classifier.md` ships embedded in the Lambda
  deployment package by default. An optional `SYSTEM_PROMPT_S3_BUCKET` override exists in
  `src/config.py`, but no CDK stack sets it, so a default deployment does not externalize
  the prompt to S3.
- **Version Control**: prompt changes are tracked the same way any other source file is —
  through this repository's own git history. There is no separate deployment-pipeline
  tracking mechanism beyond that.
- **Fallback Handling**: UNCLASSIFIED fallback on model failures or schema violations

### Tool Security
- **Read-Only Tools**: Classification tools make no state changes
- **Input Validation**: All tool inputs validated against expected schemas
- **Error Handling**: Graceful degradation on tool failures

## Network Security

### Deployment Model — No VPC

**None of this agent's Lambda functions run inside a VPC.** `infra/` declares no
`aws-cdk-lib/aws-ec2` VPC, no private subnets, and no NAT Gateway — every Lambda runs on
the standard AWS Lambda service network and reaches AWS APIs over their public endpoints
using its IAM role, the same as any default Lambda deployment. This is a deliberate choice
for a serverless prototype with no requirement to reach private/on-premises resources, not
an oversight: a VPC adds a NAT Gateway cost and cold-start/ENI overhead this design doesn't
need. If your deployment requires VPC placement (e.g. to reach a private database or
on-premises network), you would add that yourself — it is not part of this sample.

### Endpoint Security
- **HTTPS Only**: All external communications (Slack/Teams/Jira webhooks, the AWS DevOps
  Agent eventChannel webhook) are validated to start with `https://` before any request is
  made (`_validate_https()` in `src/sinks/` and `src/devops_agent/trigger.py`) — TLS
  certificate validation itself is handled by the underlying `requests`/`urllib3` library's
  default behavior, not custom code in this repository.
- **AWS service calls**: made via the AWS SDK (boto3) over its standard TLS-protected
  endpoints. No VPC endpoints are provisioned (see above), so these calls traverse the
  public AWS network backbone rather than a private VPC endpoint path.

## Incident Response

### Security Monitoring
- **CloudWatch Alarms**: `DlqDepthAlarm`, `SettleDlqDepthAlarm` (DLQ depth) and
  `ClassificationErrorAlarm` (classification error rate ≥ 5 over 2×5-minute periods) —
  `infra/lib/core-stack.ts`. There is no alarm specifically watching for unauthorized
  access attempts; that would come from CloudTrail/GuardDuty, neither of which this
  repository provisions (see "Audit Requirements," above).
- **X-Ray Tracing**: enabled on every Lambda (`tracing: lambda.Tracing.ACTIVE`)
- **Audit Logging**: audit records in DynamoDB (`AuditLog`) and standard Lambda
  CloudWatch Logs

### Breach Response
1. **Detection**: CloudWatch alarms and manual monitoring
2. **Isolation**: Disable affected Lambda functions via console
3. **Investigation**: Review audit logs and X-Ray traces
4. **Recovery**: Redeploy from known-good configuration
5. **Lessons Learned**: Update threat model and controls

### Contact Information
- **Security Issues**: Report to AWS security team via standard channels
- **Operational Issues**: Monitor CloudWatch dashboards and alarms

## Compliance Considerations

### Data Residency
- **AWS Health Data**: Processed in eu-west-1 region
- **Cross-Region**: EventBridge rules collect from all enabled regions
- **Storage**: All persistent storage in eu-west-1
- **Guardrail cross-Region inference**: the `AutonomousRemediation` denied topic runs on the
  Amazon Bedrock Guardrails `STANDARD` tier, which requires cross-Region guardrail inference. Event
  text (classified "Confidential" above) sent for guardrail evaluation may be routed to other
  Regions within the `eu.guardrail.v1:0` profile's geography — `eu-central-1`, `eu-west-1`,
  `eu-west-3`, `eu-north-1`, `eu-south-1`, `eu-south-2` — not only `eu-west-1`. This is transient
  processing (guardrail evaluation), not persistent storage; see design.md §3.3 for the
  configuration detail and why `STANDARD` was chosen over `CLASSIC`.

### Audit Requirements
- **Event Processing**: every workflow execution writes an audit record
  (`AuditLog` DynamoDB table); the table is read/write, not write-only
- **Access Logging**: this repository does not provision a CloudTrail trail. AWS API
  calls made by this agent's own roles appear in CloudTrail only if the deploying
  account already has a trail configured — that is a customer/account-level setting,
  not something `infra/` creates.
- **Change Tracking**: not implemented as a distinct control — see T3/EOP3 in the threat
  model.

### Retention Policies
- **Events**: 400 days configurable retention in S3 (the event-snapshot bucket's
  lifecycle rule)
- **Audit Logs**: no explicit retention policy is configured on `AuditLog` (DynamoDB has
  no TTL set on this table); CloudWatch Logs retention is 90 days in production /
  14 days in non-production (`infra/lib/python-lambda.ts`)
- **Secrets**: no rotation is configured (see "Encryption at Rest" and ID2, above)

## Security Maintenance

The items below are process recommendations for whoever operates a deployment of this
sample, not controls this codebase enforces automatically:

### Recommended Reviews
- **Quarterly**: IAM policy and Agent Space configuration review
- **Monthly**: Security monitoring dashboard review  
- **Weekly**: CloudWatch alarm and error rate review

### Recommended Updates and Patching
- **Dependencies**: `requirements.txt` and `package.json` both use version ranges for
  most dependencies (`esbuild`, `typescript`, and `constructs` are the exceptions —
  pinned to exact versions in `package.json`), so a fork can pick up compatible patch/
  minor releases without manual bumps. `requirements.txt`'s ranges are deliberately
  bounded below the next major version (e.g. `boto3>=1.43.103,<2.0.0`) to avoid an
  unreviewed breaking upgrade. For both ecosystems, the actual installed version is
  pinned exactly by a lockfile — `package-lock.json` (with integrity hashes) for
  Node, though this repository does not commit a Python lockfile
  (`pip freeze`/`uv.lock`/`requirements-lock.txt`) — so a fresh `pip install` can pick
  up a newer version within each range on every install, unlike the Node side. No
  automated dependency-update tooling (e.g. Dependabot) is configured — set one up
  in your own fork if you want automated update PRs.
- **Base Images**: N/A — this codebase has no Dockerfile; Lambda functions use the
  standard AWS-managed Python 3.13 runtime.
- **AWS Services**: follow AWS security bulletins for service updates.

### Testing
- **Security Scanning**: Automated Bandit, Semgrep, Checkov, cfn_nag via Probe/Slingshot
- **Penetration Testing**: Annual third-party security assessment recommended
- **Reliability Testing**: Regular evaluation runs against classification model

## Getting Security Support

For security questions or to report security issues:

1. **AWS Internal**: Follow standard AWS security reporting procedures
2. **Customers**: Use AWS Support channels for deployment-specific security questions
3. **Community**: Security-related issues on the public GitHub repository should not include sensitive details

This security documentation is maintained alongside the codebase and updated with each release to reflect current security posture and threat landscape.