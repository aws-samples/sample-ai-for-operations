# Profile v2: AgentCore Memory Publishing Guide

Profile v2 is the shared, cross-laptop version of the SaaS readiness agent. It keeps deterministic assessment state separate from model-generated memory.

## Storage responsibilities

| Component | Responsibility |
|---|---|
| AgentCore Memory blob events | Exact canonical `BQ-*` signal answers and derived-state checkpoints |
| Strands `AgentCoreMemorySessionManager` | Conversation and agent history |
| AgentCore long-term strategies | Optional summaries and semantic context |
| Amazon Bedrock Knowledge Base | Optional architecture-document retrieval |
| Local JSON | v1 demo only |

Long-term extraction and Knowledge Base ingestion are asynchronous. Neither is allowed to determine scores or whether a question has been answered. The active catalog contains 14 customer-facing `AQ-*` topics. Each topic maps to one or more closed internal `BQ-*` signals; only those classified signals affect deterministic scoring.

## Provisioning

Provision the AgentCore Memory resource before deploying the application. Configure:

- Event retention appropriate to the assessment lifecycle, up to the service-supported limit.
- A customer managed AWS KMS key when required by data-classification policy.
- Memory strategies only when semantic or summary recall is needed.
- An execution role scoped to the specific Memory resource.

Do not call a Memory create operation from application startup.

Official references:

- [AgentCore Memory](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory.html)
- [Memory organization and IAM namespace controls](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory-organization.html)
- [Strands Agents SDK integration](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/strands-sdk-memory.html)

## Runtime configuration

```bash
export SESSION_PROFILE=v2
export AGENTCORE_MEMORY_ID=<pre-provisioned-memory-id>
export AGENTCORE_REGION=us-east-1
export BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-5
export BEDROCK_REGION=us-east-1
export BEDROCK_GUARDRAIL_ID=<published-guardrail-id>
export BEDROCK_GUARDRAIL_VERSION=<published-guardrail-version>
```

`ASSESSMENT_ID` and `CONTRIBUTOR_ID` may be set for direct CLI/REPL use. The Runtime handler receives them per invocation so one deployment can serve multiple assessments.

Both IDs accept 3–128 letters, numbers, hyphens, or underscores. Contributor IDs must be pseudonymous and must not contain email addresses.

For public deployment, `BEDROCK_GUARDRAIL_ID` and `BEDROCK_GUARDRAIL_VERSION` are required together. When configured, the Strands Amazon Bedrock integration enables guardrail trace and input/output redaction. Validate the published guardrail against expected prompts and false-positive scenarios before release.

## Runtime invocation

Package the application and run:

```bash
python -m src.runtime
```

Invocation payload:

```json
{
  "assessment_id": "assessment-demo-001",
  "contributor_id": "participant-finance-02",
  "prompt": "Continue the assessment from the remaining finance questions"
}
```

Every persona uses the same assessment ID. The application derives one shared AgentCore actor/session pair from it, restores previous answers, and records contributor provenance in each event.

## Authorization boundary

The assessment ID is not a credential. A production front door must authenticate the caller and verify assessment membership before forwarding the request. Do not trust a contributor ID supplied by an unauthenticated client. The sample Runtime handler documents this boundary but does not implement an organization-specific identity provider.

## State and conflict behavior

Answer records are append-only. The adapter sorts events by service timestamp and event ID, then uses the newest event for each question. Simultaneous updates therefore use deterministic last-event-wins behavior. This is appropriate for collaborative assessment answers but is not a compare-and-swap transaction.

AgentCore Memory failures are surfaced as structured session errors. They are never interpreted as an empty assessment.

## Knowledge Base integration

`KNOWLEDGE_BASE_ID` is reserved for a future document-retrieval adapter. It should index architecture documents and runbooks, preferably with assessment metadata filters. Retrieved document evidence must remain distinct from exact answer events and must carry its own source and confidence.

## Local validation

Offline validation injects a fake Memory client and confirms:

1. Persona A writes an answer.
2. Persona B reads it from the shared assessment stream.
3. Persona B changes it.
4. Persona A reads the updated value.
5. No AWS endpoint is called.

A deployed smoke test should repeat that flow with two independently authenticated callers before external publication.
