# SaaS Readiness Agent

An AI agent, built with the [Strands Agents SDK](https://github.com/strands-agents/sdk-python) and Amazon Bedrock (Claude Sonnet 5), that assesses whether an AWS-hosted product behaves like scalable, multi-tenant SaaS, or like single-tenant software that happens to run in AWS. The assessment covers seven dimensions and 39 controls derived from the AWS Well-Architected SaaS Lens and AWS SaaS Journey Framework: tenant isolation, tenant context, tenant lifecycle, observability, deployment automation, cost attribution, and business readiness.

## Important

**This is sample code for demonstration and educational purposes only. It is not intended for production use as-is.** Review the code, the AWS permissions it requests, and the generated report before sharing it outside your own review. Work with your security and compliance teams to confirm it meets your organization's requirements before using it against a real AWS account. AWS discovery calls AWS APIs and may incur nominal charges for API usage; it never creates, modifies, or deletes AWS resources (see "Security Guardrails" below).

## How It Works

You talk to the agent (locally today, or on Amazon Bedrock AgentCore Runtime once deployed — see "Publishing the v2 AgentCore Profile" below); it decides what to investigate, calls its tools to actually score your environment, and explains the result back to you in plain language. The agent itself never invents a score, status, or confidence value — every one of those comes from a deterministic scoring engine underneath it, so results stay reproducible and auditable rather than being a model's opinion.

```
┌──────────────┐      ┌─────────────────────────┐     ┌───────────────────────┐
│ User         │────▶ │ Strands Agent           │────▶│ AWS APIs (read-only)  │
│ (CLI / chat) │      │ (Bedrock Claude Sonnet) │     │ EC2, RDS, DynamoDB,   │
└──────────────┘      │                         │     │ Cognito, CloudWatch,  │
                      │ • Tool: run assessment  │     │ CloudFront, IAM...    │
                      │ • Tool: get questions   │     └───────────────────────┘
                      │ • Tool: save answer     │
                      │ • Tool: write report    │      ┌───────────────────────┐
                      └───────────┬─────────────┘────▶ │ Deterministic scoring │
                                  │                    │ engine (assessment_   │
                                  │                    │ core.py) — the model  │
                                  │                    │ never sets a score    │
                                  ▼                    └───────────────────────┘
                      ┌─────────────────────────┐
                      │ Session store           │
                      │ v1: local JSON file     │
                      │ v2: AgentCore Memory    │
                      │     (shared, multi-     │
                      │     persona, cross-     │
                      │     laptop)             │
                      └─────────────────────────┘
```

The model only ever decides *what to call next* and *how to phrase the result*. Every score, status, and confidence value is computed once, in `src/assessment_core.py`, and handed to the model as a finished fact — it cannot override, estimate, or round a number on its own.

- `src/agent.py`: the primary AI agent. Built with the Strands Agents SDK and an Amazon Bedrock (`BedrockModel`) LLM. Wires the tools, the system prompt (`src/prompts/system_prompt.md`), and the local conversational entrypoint (`saas-readiness-agent`, or `python -m src.agent`).
- `src/tools/`: one module per tool the model can call. None of them calls the model.

  | Tool | Classification | What it does |
  |---|---|---|
  | `run_saas_readiness_assessment` | Precision | Scores the payload (and optional read-only discovery) |
  | `get_assessment_questions` | Precision | Returns unanswered questions, ranked by the weak controls they resolve |
  | `get_findings_summary` | Precision | Returns the flat findings list |
  | `save_assessment_answer` | Precision | Persists one answer and confirms it is visible (session profiles only) |
  | `get_assessment_progress` | Precision | Lists saved answers (session profiles only) |
  | `read_customer_document` | Data retrieval | Reads a file from `DOCUMENTS_DIR`. Omitted from the AgentCore Runtime profile |
  | `write_html_report` | Precision | Writes the HTML report inside the working directory |
  | `write_summary_report` | Precision | Writes the Markdown summary inside the working directory |
- `src/assessment_core.py`: the deterministic scoring engine the agent's tools call. Input handling, session answers, evidence inference, scoring, recommendations, and HTML/JSON/Markdown report rendering all live here. This module has no Strands or Bedrock dependency, so it stays independently unit-testable and is the single source of truth for every number the agent reports.
- `src/config.py`: centralized v1/v2, model, region, Memory, assessment, contributor, and optional Knowledge Base configuration.
- `src/session_store.py`: framework-free persistence contract shared by both profiles.
- `src/observability.py`: structured JSON logging for the AgentCore Runtime entrypoint and AWS discovery (never logs prompts, responses, or answers).
- `src/agentcore_session_store.py`: v2 adapter that stores canonical answers as AgentCore Memory blob events.
- `src/session_profiles.py`: lazy profile construction and Strands AgentCore Memory session-manager wiring.
- `src/runtime.py`: publishable Amazon Bedrock AgentCore Runtime entrypoint for v2.
- `src/rubric.py`: static source-backed dimensions, controls, questions, and public AWS references.
- `src/discovery.py`: read-only AWS discovery adapter (the only module that calls AWS APIs on the customer's behalf). Runs a two-stage inspection: cheap Stage 1 classification (identity, IaC signal, tagging, VPC topology) followed by conditional Stage 2 service checks (compute, data stores, identity, observability, cost, edge/CDN presence, agentic-SaaS surfaces).
- `src/explainer.py`: optional one-shot LLM narrative adapter used only by the `saas-readiness-assess` deterministic CLI's `--explain bedrock` flag (see "Deterministic CLI" below). Deterministic code always owns scores/statuses; this adapter can only add prose on top of an already-finished result. Defaults to `NoopExplainer` (no model call).
- `src/mcp_server.py`: optional thin MCP wrapper over the same deterministic scoring function, for use from MCP-compatible clients (Claude Desktop, Kiro, Amazon Q, Cursor, etc.).
- `tests/unit/`: unit tests. `tests/unit/tools/` has one test file per tool, `tests/unit/test_agent.py` covers agent wiring, and the rest cover the deterministic core, AWS discovery (against a fake client factory, no real AWS calls), and the explanation adapter.
- `.kiro/specs/saas-readiness-agent/`: the master specification (requirements, design, and tasks) the agent is built from. Start here to understand or extend it.

The goal is not to count AWS resources. The goal is to decide, from available evidence, whether the platform behaves like scalable SaaS across tenant isolation, tenant context, lifecycle, operations, deployment, cost attribution, and business readiness.

## Prerequisites

- Python 3.12 or later
- Amazon Bedrock access with the Claude Sonnet 5 model enabled in your account/region — required to run the agent (`src/agent.py`)
- AWS credentials configured (SSO, IAM role, or environment variables) — only required when the agent runs AWS discovery against your account
- (Optional) The read-only IAM policy in [`docs/iam/discovery-minimum-policy.json`](docs/iam/discovery-minimum-policy.json) (or `discovery-enhanced-policy.json` for `enhanced_assessment`) — needed for AWS discovery to see everything it's designed to check. Both are generated from `MINIMUM_READ_ONLY_ACTIONS` / `ENHANCED_READ_ONLY_ACTIONS` in `src/discovery.py`.

## Installation

```bash
git clone <repo-url>
cd saas-readiness-agent
python3 --version  # confirm Python 3.12+
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # pinned, tested dependency versions
pip install -e . --no-deps        # installs the `src` package and the two console scripts
```

`requirements.txt` pins everything needed to run the agent: the Strands Agents SDK, the Strands Bedrock model provider, `boto3` (AWS discovery and Bedrock calls), the Bedrock AgentCore Runtime SDK (so the same code can deploy to AgentCore Runtime), and the MCP package (for `src/mcp_server.py`). The second command installs this project itself without changing those pinned versions, and provides the `saas-readiness-agent` and `saas-readiness-assess` commands.

If you're contributing to the project rather than just running it, also install the dev tools (pytest, coverage, mypy, ruff):

```bash
pip install -e ".[dev]"
```

## Usage

### Run the agent (primary way to use this project)

Run from the repository root with the virtual environment active:

```bash
saas-readiness-agent
# equivalent: python -m src.agent
```

To let the agent read your architecture documents, copy them into `documents/` at the repository root (or point `DOCUMENTS_DIR` at another directory) and give the agent the file names. The document reader refuses any path outside that directory, including `..` traversal and symlinks that point elsewhere.

This starts a local conversational session. Tell it what you want assessed:

```
You: Assess my AWS account for SaaS readiness
You: Here's a JSON payload with facts about my architecture: {...}
You: Write the HTML report to reports/my-assessment.html
```

The agent decides which tool to call based on what you ask:

- To assess a live AWS account, it calls `run_saas_readiness_assessment` with `discover_aws=true`, which runs the read-only AWS discovery pipeline (Describe/List/Get/Simulate calls only — see "AWS Discovery" below) against whatever credentials are active in your environment.
- To assess a JSON payload you provide, it passes your JSON through `input_json` instead.
- To save a report, it calls `write_html_report` (`.html` only) or `write_summary_report` (`.md` only). Both write only inside the reports directory (`REPORTS_DIR`, default `reports/`), so a steered path cannot overwrite source files, `README.md`, or session data.

The recommended flow is:

1. **AWS discovery and documents first** — the agent scans the account for read-only signals and reads supplied architecture material.
2. **Adaptive 14-topic conversation** — it asks only unresolved customer topics, one at a time, and routes each topic to the best persona. A well-documented environment may need only a subset; the conditional compliance topic appears only when relevant.
3. **Re-score with evidence** — the deterministic engine merges observed signals, reviewed evidence, and conservative customer assertions.
4. **Snapshot report** — HTML and Markdown lead with coverage, score rationale, three priorities, and one deeper-engagement route; control detail stays in an appendix.

The model ID and region are configurable via the `BEDROCK_MODEL_ID` and `BEDROCK_REGION` environment variables (defaults: `us.anthropic.claude-sonnet-5` and `us-east-1`).

### Deterministic CLI (no LLM, no conversation)

If you want to run the assessment without any model call at all — for scripting, CI, or a fully deterministic run — use the `saas-readiness-assess` console script, which calls the same `assess_payload()` scoring engine directly:

```bash
saas-readiness-assess assess --discover-aws --output reports/assessment.html
saas-readiness-assess questions                                  # see which fixed business-context questions are unanswered
saas-readiness-assess answer-set --question-id BQ-001 --value pooled
saas-readiness-assess answers                                     # review saved answers
```

Answers from `answer-set` are saved to `sessions/session.json` and merged into every later `assess` run as evidence.

Additional output artifacts (all optional, written alongside the primary HTML report):

```bash
saas-readiness-assess assess \
  --discover-aws \
  --output reports/assessment.html \
  --assessment-json reports/assessment.json \
  --findings-json reports/findings.json \
  --summary-md reports/summary.md
```

- `--assessment-json`: the full canonical machine-readable result.
- `--findings-json`: every scored control flattened into one normalized findings list (`dimension`, `status`, `evidence_state`, `why_it_matters`, `evidence`, `recommended_next_step`, `source_refs`).
- `--summary-md`: a short customer-facing Markdown narrative.
- `--explain bedrock`: adds a one-shot model-generated executive-summary paragraph to `summary.md` only. It cannot change any score, status, or confidence value — see `src/explainer.py`'s module docstring for why. `--explain none` (the default) makes zero model calls.

### Try It With Demo Data

`samples/minimal_assessment.json` is a synthetic fixture used for testing and for seeing what a report looks like without touching a real AWS account. It contains no real customer data (see the fixture's own `scope.notes` field).

```bash
saas-readiness-assess assess --input samples/minimal_assessment.json --output reports/sample-report.html --no-session
```

## What The Agent Checks

The rubric has seven dimensions and 39 controls:

- Tenant Architecture and Isolation
- Identity and Tenant Context
- Tenant Lifecycle and Onboarding
- Observability and Operational Readiness
- Deployment and Platform Automation
- Cost Attribution and Metering Readiness
- Service Model and Business Readiness

Status scoring is deterministic:

- `met` = `1.0`
- `partial` = `0.5`
- `missing` = `0.0`
- `unknown` = excluded from raw score but lowers confidence
- `not_applicable` = excluded from score and confidence penalty

Missing permissions become `unknown` evidence gaps. Inspected-but-absent capabilities become `missing`. Explicit evidence wins over inferred evidence.

## AWS Discovery

AWS discovery runs the full read-only pipeline in `src/discovery.py`, whether triggered by the agent (`run_saas_readiness_assessment` with `discover_aws=true`) or by the deterministic CLI (`saas-readiness-assess assess --discover-aws`):

- **Stage 1 (cheap classification)**: caller identity + IAM permission simulation, CloudFormation stack presence (IaC signal), a bounded sample of customer-defined tag keys/resources (suggestive cost-allocation signal only), VPC/security-group topology, and (in `enhanced_assessment` access mode only) AWS Organizations account count.
- **Stage 2 (conditional deepening)**: only runs once Stage 1 suggests a service is in use — Lambda/ECS/EKS/EC2 compute presence, DynamoDB/RDS/S3 data-store presence (including a tenant-shaped-partition-key heuristic on a sampled DynamoDB table), Cognito/Secrets Manager identity-layer presence, CloudWatch alarms/metrics and log-group observability signals, CloudFront/ACM/WAFv2 per-tenant edge signals (custom domain + TLS + edge protection), Bedrock AgentCore runtime/gateway presence (informational only) and per-tenant-named S3 Vectors indexes (suggestive `agent_memory_isolation` signal for agentic-SaaS surfaces), and (enhanced mode only) a Cost Explorer reachability check.

Every discovery call is Describe/List/Get/Simulate only — nothing mutates a customer resource. If a permission is denied or an unexpected AWS/network error occurs, the affected controls become `unknown` evidence with lowered confidence instead of failing the assessment. Minimum vs. enhanced read-only IAM actions are listed in `src/discovery.py` (`MINIMUM_READ_ONLY_ACTIONS`, `ENHANCED_READ_ONLY_ACTIONS`).

The service-aware logic includes API Gateway, Lambda, DynamoDB, ECS, EKS, EC2, RDS/Aurora, S3, KMS, ElastiCache, OpenSearch, SQS, SNS, EventBridge, Kinesis, Redshift, Cognito, IAM, Secrets Manager, Route 53, load balancers, CloudFront, ACM, WAFv2, CloudWatch, CloudTrail, Organizations, Control Tower, Cost Explorer, Amazon Bedrock AgentCore, and S3 Vectors.

Databases running on EC2 are treated as first-class data layers. The engine recognizes common self-managed database signals such as PostgreSQL, SQL Server, Oracle, MySQL, MariaDB, MongoDB, DB2, and SAP HANA when they appear with EC2, or when `self_managed_database_on_ec2` is supplied. The report calls out tenant isolation, host and security-group boundaries, patching, backups, encryption, tenant-aware database telemetry, and EC2/EBS cost attribution.

AI/ML services such as Amazon Bedrock and Amazon SageMaker trigger an optional advisory overlay. They do not improve the default maturity score by their presence alone.

## Publishing the v2 AgentCore Profile

The local demo runs profile v1. The publishable entrypoint is `src/runtime.py`, which uses Amazon Bedrock AgentCore Memory for both shared structured answers and Strands conversation restoration.

Before deploying, provision one AgentCore Memory resource with the required retention and encryption settings. The application never creates that resource at startup. Configure the runtime with:

```bash
SESSION_PROFILE=v2
AGENTCORE_MEMORY_ID=<pre-provisioned-memory-id>
AGENTCORE_REGION=us-east-1
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-5
BEDROCK_REGION=us-east-1
```

The repository includes a `Dockerfile` that packages `src/` and the pinned `requirements.txt` into a `linux/arm64` image (Python 3.12 slim base, non-root user) whose entrypoint is `python -m src.runtime`. Build it and push it to an Amazon ECR repository in your account:

```bash
docker buildx build --platform linux/arm64 -t saas-readiness-agent:latest --load .
docker tag saas-readiness-agent:latest <account-id>.dkr.ecr.<region>.amazonaws.com/saas-readiness-agent:latest
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/saas-readiness-agent:latest
```

Then create an AgentCore Runtime from that image URI, with the environment variables above and inbound authentication configured (IAM SigV4 or a JWT authorizer). AgentCore Runtime is the only ingress; the image publishes no host port on its own. To smoke-test the container locally, publish the port to loopback only:

```bash
docker run --rm -p 127.0.0.1:8080:8080 --env-file .env saas-readiness-agent:latest
curl -s http://127.0.0.1:8080/ping
```

The runtime writes structured JSON logs (one object per line) to stderr, which AgentCore Runtime forwards to Amazon CloudWatch Logs. Events are `invocation_started`, `invocation_completed`, `invocation_failed`, and `aws_discovery_call_failed`. They carry identifiers, durations, model ID, AWS error codes, and exception types only, never prompts, model responses, or customer answers. The local REPL and CLI do not emit these logs. Separately, the AgentCore Runtime SDK logs unhandled invocation errors with the exception message and stack trace; treat the runtime log group as potentially containing request-derived text and restrict access to it accordingly.

Optional runtime settings (all have safe defaults):

| Variable | Default | Purpose |
|---|---|---|
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `DOCUMENTS_DIR` | `documents` | The only directory `read_customer_document` may read (local REPL only; the tool is not available in the AgentCore Runtime profile). |
| `REPORTS_DIR` | `reports` | The only directory `write_html_report` and `write_summary_report` may write to, relative to the working directory. |
| `MAX_INPUT_JSON_BYTES` | `262144` | Rejects oversized `input_json` tool payloads before parsing. |
| `BEDROCK_MAX_TOKENS` | `4096` | Caps output tokens per model call. |
| `AWS_DISCOVERY_MAX_ATTEMPTS` | `5` | Total attempts per discovery API call, including retries of throttling and transient network errors. |
| `AWS_DISCOVERY_RETRY_MODE` | `adaptive` | botocore retry mode: `legacy`, `standard`, or `adaptive`. |

Each invocation supplies the authorized assessment and pseudonymous contributor identifiers:

```json
{
  "assessment_id": "assessment-demo-001",
  "contributor_id": "participant-platform-01",
  "prompt": "Continue this SaaS readiness assessment"
}
```

The caller-facing authentication layer must verify that the contributor belongs to the requested assessment. An assessment ID routes state; it is not an authorization secret. See [`docs/deployment-security.md`](docs/deployment-security.md) for an example JWT authorizer configuration and two ways to enforce assessment membership. Scope the runtime role to the configured Memory resource and the AgentCore Memory event operations used by the adapter and Strands session manager. Add the read-only discovery permissions from `src/discovery.py` only when the published agent will scan its deployment account.

## Security Guardrails

See [SECURITY.md](SECURITY.md) for the security boundary, data handling, Responsible AI, and Amazon Bedrock Guardrail guidance.

- **Do not include sensitive personal information in your prompts.** The agent processes inputs through Amazon Bedrock — avoid including PII, credentials, or confidential data in your questions or JSON payloads.
- Level 0 against customer environments: discovery uses only Describe/List/Get/Simulate APIs. Profile v2 writes assessment-owned events only to the configured AgentCore Memory resource.
- The agent's tools (`src/tools/`) never accept a parameter through which the model could write a different score, status, or confidence value than what `assess_payload()` computed — see the tool docstrings and the structural tests in `tests/unit/tools/`.
- Use least-privilege read-only access and preflight permission checks (`MINIMUM_READ_ONLY_ACTIONS`, `ENHANCED_READ_ONLY_ACTIONS` in `src/discovery.py`). The agent is read-only by default against customer environments.
- For a public deployment, configure a tested, published Amazon Bedrock Guardrail through `BEDROCK_GUARDRAIL_ID` and `BEDROCK_GUARDRAIL_VERSION`. An example guardrail definition is in [`docs/examples/guardrail.json`](docs/examples/guardrail.json). When configured, the model integration enables guardrail tracing and input/output redaction.
- Redact common account IDs, ARNs, emails, access keys, passwords, tokens, and secrets from output (`Redactor` in `src/assessment_core.py`), applied to session answers, evidence, and every rendered report/artifact.
- Keep sample files synthetic. Do not add customer identifiers, tenant names, logs, secrets, or real cost data.
- Validate local input, output, and session paths to prevent path traversal (`safe_path` in `src/assessment_core.py`; the agent's `write_html_report`/`write_summary_report` tools are stricter: they write only `.html`/`.md` files inside `REPORTS_DIR`, resolved including symlinks).
- The model-driven document reader (`read_customer_document`) reads only inside `DOCUMENTS_DIR`. Paths are fully resolved (including symlinks) before the containment check, and the tool is removed from the AgentCore Runtime profile. Document content is treated as data; the system prompt tells the model never to follow instructions found in documents.
- Return structured errors instead of raw tracebacks (`AssessmentError` subclasses).
- The optional `--explain bedrock` one-shot narrative layer (deterministic CLI only) cannot change any score, status, or confidence value; see "Deterministic CLI" above.

## Session Profiles and Multi-Persona Assessments

The project ships two profiles over the same deterministic scoring engine.

### v1 — local demo (default)

Profile v1 stores exact answers in `sessions/session.json` and never initializes AgentCore Memory. Use it for laptop demos and offline development:

```bash
export SESSION_PROFILE=v1
saas-readiness-agent

saas-readiness-assess answer-set --question-id BQ-001 --value pooled
saas-readiness-assess answers
saas-readiness-assess assess --output reports/assessment.html
```

You can also pass `--session-profile v1` to deterministic CLI commands. Local state is intentionally not shared between laptops.

### v2 — published, cross-laptop assessment

Profile v2 stores canonical `BQ-*` answers as synchronous, append-only blob events in Amazon Bedrock AgentCore Memory. It also configures the Strands `AgentCoreMemorySessionManager` so another authorized persona using the same assessment ID receives prior conversational context.

For a direct v2 CLI or local integration smoke run, configure:

```bash
export SESSION_PROFILE=v2
export AGENTCORE_MEMORY_ID=<pre-provisioned-memory-id>
export ASSESSMENT_ID=assessment-demo-001
export CONTRIBUTOR_ID=participant-platform-01
export AGENTCORE_REGION=us-east-1
saas-readiness-agent
```

A second participant uses their own AWS credentials and contributor ID, but the same Memory and assessment IDs. The agent loads saved answers, calls `get_assessment_progress`, skips completed questions, and continues with the remaining persona-specific gaps.

`src/session_store.py` defines the shared contract. `JsonSessionStore` implements v1; `AgentCoreMemorySessionStore` in `src/agentcore_session_store.py` implements v2. `src/session_profiles.py` constructs the selected backend lazily, so v1 does not need AgentCore credentials.

AgentCore short-term blob events are the exact source of truth for scoring. Long-term semantic or summary memory can improve conversational continuity, but asynchronous extracted memories never change deterministic scores. Last-event-wins semantics apply when two personas update the same question.

### Optional Knowledge Base documents

`KNOWLEDGE_BASE_ID` is reserved for optional retrieval over customer architecture documents and runbooks. Amazon Bedrock Knowledge Bases are not used as the transactional answer store. Document retrieval and structured AgentCore Memory state remain separate concerns.

See [`docs/agentcore-memory-v2.md`](docs/agentcore-memory-v2.md) for provisioning, authorization, lifecycle, and validation guidance.

## Limitations

- Single-account assessments have limited confidence about organization-wide tenancy patterns; use `access_mode: enhanced_assessment` (and the matching IAM permissions) for AWS Organizations visibility.
- AWS discovery observes AWS resource shape and naming; it cannot see application code, so tenant isolation and tenant-context findings from discovery are always `suggestive`, never `confirmed`, unless corroborated by explicit evidence you supply.
- Running the agent requires Amazon Bedrock access in your account/region. If you don't have that, use the deterministic CLI (`saas-readiness-assess`) instead, which never calls a model unless you explicitly pass `--explain bedrock`.
- The MCP server (`src/mcp_server.py`) is installed by default via `requirements.txt` but has not been validated against every MCP client.

## Design Principles

- **Observe and report in customer environments.** Discovery never mutates customer resources. Profile v2 may write assessment-owned state to its explicitly configured AgentCore Memory resource.
- **The model explains, deterministic code scores.** `src/assessment_core.py` has zero Strands or Bedrock imports and is independently unit-tested; the agent's tools only ever return what it already computed.
- **Targets well-documented anti-patterns.** The rubric is derived from the AWS Well-Architected SaaS Lens and AWS SaaS Journey Framework, and specifically targets common anti-patterns: missing tenant isolation, mistaking authentication for isolation, no tenant-aware observability, missing cost-per-tenant visibility, manual onboarding, and version drift.
- **Standalone.** This tool has no required handoff or dependency on any other AWS engagement or program. It can suggest relevant AWS engagements in its output (see "Suggested Follow-Up" in the generated report) when findings warrant it, but produces a complete, useful report on its own.

## Tests

```bash
pytest tests/ -v
python3 -m compileall src tests
```

Test coverage (`make test-coverage`) is above the project's 80% coverage gate. Tests never call a real Amazon Bedrock model or real AWS APIs: each tool is tested by calling its plain (undecorated) function directly (`tests/unit/tools/`), AWS discovery is tested against a fake client factory (`tests/unit/test_discovery.py`), and the one-shot explanation adapter is tested against a fake Amazon Bedrock client (`tests/unit/test_explainer.py`).

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.


## Engagement Positioning

The SaaS Readiness Agent is an **evidence-first front door** for customers who want a holistic initial SaaS view but are not yet ready for a formal assessment. It combines read-only AWS signals, customer documentation, and an adaptive 14-topic conversation across Product, Platform, Architecture, Operations, Finance, and Customer Success.

The resulting **SaaS Readiness Snapshot** clearly separates observed evidence, customer assertions, and unverified gaps. A result remains **Provisional** until at least 70% of controls are assessed and all seven dimensions have a score. The report explains each dimension score, shows three ranked actions, links to public AWS guidance, and recommends one deeper path when appropriate.

It does not replace a formal SaaS Maturity Assessment, Automated SMA, or a Well-Architected review. Typical routes are:

- Tenant isolation or tenant-context gaps → formal SaaS Lens review through the approved AWS review mechanism.
- Strong IaC readiness → Automated SMA.
- Packaging, service model, or unit-economics gaps → AWS account team-led SaaS Maturity Assessment or SaaS Compass/Factory guidance.

The official AWS Well-Architected Agent currently covers the main framework at launch; SaaS Lens parity is roadmap work. Do not position it as an automated SaaS Lens review today.
