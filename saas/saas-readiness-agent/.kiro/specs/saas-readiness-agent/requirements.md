# SaaS Readiness Agent — Requirements

This is the master specification for the SaaS Readiness Agent. It describes
what the agent does and why. Update it whenever behavior changes.

## Product intent

The SaaS Readiness Agent is an evidence-first front door for software vendors
considering a SaaS engagement. It gives a holistic initial maturity view across
seven dimensions, explains why each score was produced, identifies the
highest-value improvements, and points the customer to the right deeper AWS
engagement without trying to replace it.

It is sample code for demonstration and education. It is not a formal SaaS
Maturity Assessment, Automated SMA, or AWS Well-Architected review.

## Users

- **Assessment contributors:** product, platform, architecture, operations,
  finance, and customer-success personas at the vendor, who answer questions
  for one shared assessment.
- **Operator / deployer:** the vendor engineer who runs the local CLI with
  their own AWS credentials, or deploys the agent to Amazon Bedrock AgentCore
  Runtime.

## Functional requirements

### Assessment

1. Assess seven dimensions: Tenant Architecture & Isolation, Identity & Tenant
   Context, Tenant Lifecycle & Onboarding, Observability & Operational
   Readiness, Deployment & Platform Automation, Cost Attribution & Metering,
   and Service Model & Business Readiness.
2. Deterministic code computes every control status, score, confidence value,
   coverage figure, recommendation, and engagement route. The model never
   computes or changes a score.
3. Explicit reviewed evidence outranks technical signals, which outrank
   customer assertions. Unknowns and missing permissions lower confidence
   instead of counting as missing maturity.
4. Customer assertions can produce `partial`, `missing`, `not_applicable`, or
   no evidence, but never a technical `met`.

### Evidence gathering

5. Observe before asking: run read-only AWS discovery and read supplied
   documents before asking questions.
6. AWS discovery calls only Describe, List, Get, and Simulate APIs with the
   caller's own credentials. It never calls a mutating AWS API.
7. Discovery failures (missing SDK, denied permission, throttling) become
   `unknown` evidence, not a failed assessment.
8. The document reader reads only from `DOCUMENTS_DIR`, after resolving `..`
   and symlinks. It is removed from the AgentCore Runtime profile.

### Questions

9. The catalog contains 14 customer-facing `AQ-*` topics across Product,
   Platform, Architecture/Security, SRE, Finance, and Customer Success personas.
10. Each topic maps to one or more canonical `BQ-*` signals with closed options
    and deterministic control mappings. Existing signal meanings stay stable;
    new signals extend the namespace.
11. Ask only unresolved questions, one at a time. Accept "unknown" or "skip"
    without treating missing knowledge as missing maturity.
12. Support `essential` mode (essential topics only) and `full` mode (all
    topics). `all` is an alias of `full`; any other mode is rejected.

### Reports

13. Label results provisional until at least 70% of controls are assessed and
    all seven dimensions have a score.
14. Show status, overall maturity, coverage, confidence, a seven-dimension
    summary with score rationale, three ranked actions (Now / Next / Later),
    and one primary deeper-engagement route. Full controls, gaps,
    methodology, and public AWS references go in an appendix.
15. HTML and Markdown reports present the same information. Canonical JSON
    outputs change only by adding fields.
16. The report-writing tools write only `.html`/`.htm` or `.md` files inside
    `REPORTS_DIR` (default `reports/`).
17. Customer-facing references use public AWS sources only.

### Session profiles

18. **v1 local** (default): answers are stored in a local JSON file. Selecting
    v1 never constructs an AWS or AgentCore Memory client.
19. **v2 published:** answers are stored as synchronous, append-only blob
    events in a customer-provisioned Amazon Bedrock AgentCore Memory resource,
    and Strands conversation history is persisted through
    `AgentCoreMemorySessionManager` (`batch_size=1`). Every persona using the
    same assessment ID loads prior answers and continues with only the
    remaining questions.
20. Stored records include schema version, catalog version, assessment ID,
    source, pseudonymous contributor ID, and timestamp. Remote events fold
    deterministically: the newest answer per question wins.
21. Store read/write failures return structured errors and never silently
    become an empty assessment. Concurrent saves in one process neither crash
    nor lose answers.
22. The application never creates AgentCore Memory resources at startup.
    Amazon DynamoDB is out of scope; Amazon Bedrock Knowledge Bases are
    optional document retrieval only, never the source of truth for answers.

## Security and responsible AI requirements

- Customer environments are read-only. Writes are limited to agent-owned
  state: local session and report files, or the configured Memory resource.
- Assessment IDs are workflow identifiers, not authorization tokens. A
  deployed front door must authenticate callers and enforce assessment
  membership.
- Contributor IDs are pseudonymous and must not be email addresses.
- Assessment and contributor IDs must match `^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$`.
- Redact account IDs, ARNs, emails, access keys, passwords, tokens, and
  secrets before persistence and in every report.
- Bound tool input (`MAX_INPUT_JSON_BYTES`) and model output
  (`BEDROCK_MAX_TOKENS`).
- Support an optional Amazon Bedrock Guardrail (`BEDROCK_GUARDRAIL_ID` and
  `BEDROCK_GUARDRAIL_VERSION`, set together).
- Logs carry identifiers, durations, and error types only, never prompts,
  answers, or model responses.
- Treat document and discovered content as data, never as instructions.
- IAM permissions are scoped to the configured Memory resource; event
  retention is set during provisioning to match the assessment lifecycle.

## Out of scope

- Infrastructure provisioning (no CDK or CloudFormation in the sample).
- Caller authentication and authorization for the hosted runtime.
- Automatic migration of local answers to the published profile.
- Remediation of customer resources.
