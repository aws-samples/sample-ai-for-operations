# SaaS Readiness Agent — Design

## Architecture

```text
Operator (local CLI)        Caller (AgentCore Runtime, deployer-provided auth)
        │                                   │
   src/agent.py main()                 src/runtime.py invoke()
        └──────────────┬────────────────────┘
                       ▼
        Strands agent loop + Amazon Bedrock model
        (system prompt: src/prompts/system_prompt.md)
                       │ tool calls
                       ▼
        src/tools/  (one module per tool, pure code)
                       │
      ┌────────────────┼─────────────────┬───────────────────┐
      ▼                ▼                 ▼                   ▼
 assessment_core   discovery.py     doc_reader.py      session stores
 (scoring,         (read-only       (DOCUMENTS_DIR,    v1 JsonSessionStore
  reports,          boto3)           local only)       v2 AgentCoreMemorySessionStore
  Redactor)
```

The model decides what to call and how to explain the result. Every number
comes from deterministic code. `src/assessment_core.py`, `src/rubric.py`, and
`src/discovery.py` have no Strands or Bedrock imports, so they stay
independently testable.

An optional MCP server (`src/mcp_server.py`, stdio) exposes the same scoring
function to MCP clients.

## Tools

Each tool lives in its own module under `src/tools/`. `src/tools/__init__.py`
assembles the default set and the session-aware set; session-aware variants
merge persisted answers into every payload before calling deterministic code.
Shared input validation and path guards live in `src/tools/_common.py`.

| Tool | Classification | Input | Output |
|---|---|---|---|
| `run_saas_readiness_assessment` | Precision | JSON payload, discovery flag | canonical assessment result |
| `get_assessment_questions` | Precision | JSON payload, mode | unanswered questions ranked by weak controls |
| `get_findings_summary` | Precision | JSON payload, discovery flag | normalized findings |
| `save_assessment_answer` | Precision | question ID, classified value, source | persisted and verified answer (session profiles) |
| `get_assessment_progress` | Precision | none | saved answers (session profiles) |
| `read_customer_document` | Data retrieval | file name in `DOCUMENTS_DIR` | extracted content (local profile only) |
| `write_html_report` | Precision | JSON payload, path in `REPORTS_DIR` | status message |
| `write_summary_report` | Precision | JSON payload, path in `REPORTS_DIR` | status message |

No tool invokes a model. The system prompt requires saving each classified
answer immediately and forbids the model from writing scores or statuses.

## Question contract

`src/questions.py` is the only executable question catalog. It owns the 14
`AQ-*` topics, persona, phase, priority, probes, control metadata, canonical
`BQ-*` signal options (currently `BQ-001` to `BQ-029`), option-to-control
mappings, and the catalog version. `src/rubric.py` owns dimensions, the 39
controls, weights, recommendations, and public sources.

Original signal meanings are preserved: `BQ-001` tenancy model, `BQ-002`
tenant identity source, `BQ-003` context propagation, `BQ-004` onboarding
automation, `BQ-005` business stage, `BQ-006` target segment, `BQ-007` pricing
model, `BQ-008` noisy-neighbour controls, `BQ-009` release process, `BQ-010`
special isolation/compliance requirements, `BQ-011` tenant-aware operations,
`BQ-012` tenant usage/metering. Later signals cover growth pressure, service
model, lifecycle, registry, data boundary, version model, cost model,
allocation, tiers, metering, tier changes, outcomes, authorization,
privileged access, and feedback.

## Evidence and scoring

`ANSWER_CONTROL_RULES` maps exact options to exact controls. Unknown, skipped,
and unrecognized values add no evidence. Customer evidence is
`customer_asserted` with medium confidence and cannot produce technical `met`.

Evidence precedence: explicit reviewed evidence, then live or supplied
technical signals, then customer assertions, then applicability and
permission/scope unknowns. Maturity gates stop a strong average from hiding
weak fundamentals.

`CoverageResult` reports assessed, total, scoreable, unknown, and
not-applicable controls, the coverage ratio, and evidence-source counts.
Baseline status requires `BASELINE_COVERAGE_THRESHOLD` (0.70) and a scoreable
control in every dimension. Coverage qualifies presentation only; it does not
change scores.

## Discovery

Stage 1 (always, cheap): identity, account and organization shape, VPC layout,
IaC signal, tagging signal. Stage 2 (conditional): a service's Describe/List
calls run only after a presence probe suggests the account uses it (compute,
data stores, identity, observability, cost, edge, agentic surfaces). Retries
are bounded by `AWS_DISCOVERY_MAX_ATTEMPTS`. Required read-only actions are
listed in `MINIMUM_READ_ONLY_ACTIONS` and `ENHANCED_READ_ONLY_ACTIONS`.

## Session profiles

`src/config.py` centralizes and validates configuration; no other module reads
the environment directly.

| Setting | v1 | v2 |
|---|---|---|
| `SESSION_PROFILE` | default `v1` | `v2` |
| `SESSION_PATH` | local JSON path | unused |
| `AGENTCORE_MEMORY_ID` | unused | required |
| `ASSESSMENT_ID` | optional | required |
| `CONTRIBUTOR_ID` | optional | required, pseudonymous |
| `AGENTCORE_REGION` | unused | defaults to model region |
| `KNOWLEDGE_BASE_ID` | optional metadata | optional document retrieval |

`src/session_profiles.py` imports AgentCore code lazily, only for v2.

**v1:** `JsonSessionStore` holds a per-instance lock across each
read-modify-write cycle and writes through a unique temporary file, so
concurrent saves in one process cannot crash or drop answers.

**v2:** each assessment gets one actor/session pair derived from the validated
assessment ID:

```text
actorId   = saas-readiness-assessment-<assessment-id>
sessionId = saas-readiness-workflow-<assessment-id>
```

All personas on that assessment share the pair; contributor identity is event
metadata, not a partition key. Answers are immutable blob events:

```json
{
  "schema_version": 2,
  "catalog_version": 1,
  "record_type": "answer",
  "assessment_id": "assessment-abc123",
  "question_id": "BQ-001",
  "answer_value": "pooled",
  "source": "agent",
  "contributor_id": "participant-7f3a",
  "timestamp": "2026-09-15T14:30:00+00:00"
}
```

`derived_current` events record which output reflects the latest answers. The
adapter ignores unrelated events and folds the newest answer per question by
timestamp and event ID. `save_assessment_answer` confirms visibility with a
bounded retry so brief read-after-write lag never reaches the model. Long-term
memory summaries never feed scoring.

## Reports

`render_html_report()` and `build_summary_markdown()` share one hierarchy:
status and scope, coverage, seven-dimension summary, Now/Next/Later actions,
one primary engagement route, then an appendix. Every dynamic value in HTML is
escaped. The report writers resolve `output_path` (including symlinks) and
accept only `.html`/`.htm` or `.md` inside `REPORTS_DIR`, checked before any
assessment work.

## Security controls

| Control | Where |
|---|---|
| Read-only discovery, no mutating calls | `src/discovery.py` |
| Least-privilege IAM policies generated from the action lists | `src/iam_policies.py`, `docs/iam/` |
| Input-size and output-token caps | `src/tools/_common.py`, `src/agent.py` |
| Document containment, removed from runtime | `src/doc_reader.py`, `src/runtime.py` |
| Report path confinement | `src/tools/_common.py` |
| Redaction before persistence and rendering | `Redactor` in `src/assessment_core.py` |
| Safe identifiers | `src/config.py` |
| Optional Amazon Bedrock Guardrail | `src/agent.py`, `src/config.py` |
| Logging without content | `src/observability.py`, `src/runtime.py` |
| Non-root, digest-pinned container | `Dockerfile` |

See `SECURITY.md` for the STRIDE threat-model summary and deployment
assumptions, and `docs/deployment-security.md` for example IAM, inbound
authentication, and guardrail configuration.

## Testing

Unit tests live in `tests/unit/`, with one file per tool in
`tests/unit/tools/`. Tests never call a real model or AWS: discovery uses a
fake client factory and the explainer a fake Bedrock client. Coverage gate:
80%. The v2 AgentCore Memory store has been validated in live walkthroughs but
has no unit tests yet (see `tasks.md`).
