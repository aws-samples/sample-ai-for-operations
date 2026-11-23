# Security and Responsible AI

## Security boundary

This repository is sample code for assessment and demonstration. It is not production-ready as-is. Before any public deployment, perform an organization-specific security review, threat model, IAM review, privacy review, and content security scan of the exact release commit.

The agent follows a Level 0 customer-environment boundary:

- AWS discovery uses only documented read-only `Describe`, `Get`, `List`, and `Simulate` operations.
- The agent never creates, updates, deletes, or remediates customer AWS resources.
- V2 writes only assessment-owned state to the explicitly configured Amazon Bedrock AgentCore Memory resource.
- Assessment IDs are workflow identifiers, not authorization credentials. A deployed front door must authenticate callers and enforce assessment membership.

## Threat model

This release was threat modeled with the STRIDE method. The summary below lists every threat, its severity, its mitigation, and the residual decision. Every mitigation marked as in place was checked against the code.

### Risk summary

Severity in this table is the inherent rating **before** mitigation. After mitigation, residual ratings are lower: no threat remains High. The three High threats reduce to:

| Threat | Inherent | Residual | Decision |
|---|---|---|---|
| T001 Cross-assessment access | High | Medium (unlikely) | Accepted; requires the deployer's authenticating front door |
| T009 Document reader path traversal | High | Low (unlikely) | Mitigated |
| T014 Prompt injection changing customer resources | High | Low (unlikely) | Mitigated |

Each finding below states its residual decision.

| STRIDE category | High | Medium | Low | Total |
|---|---|---|---|---|
| Spoofing | 1 | 0 | 1 | 2 |
| Tampering | 0 | 3 | 1 | 4 |
| Repudiation | 0 | 0 | 1 | 1 |
| Information disclosure | 1 | 2 | 1 | 4 |
| Denial of service | 0 | 1 | 1 | 2 |
| Elevation of privilege | 1 | 0 | 1 | 2 |
| **Total** | **3** | **6** | **6** | **15** |

Residual decisions: 10 mitigated, 5 accepted, 0 open.

### Findings

#### Spoofing

- **[HIGH] T001 — Cross-assessment access in a shared v2 deployment.** A caller sends another assessment's ID to read or overwrite its answers and history. Component: `src/runtime.py`, AgentCore Memory. Mitigation: IDs are validated as safe identifiers (`src/config.py`) and the Memory partition is derived from them, but the sample has no caller authorization. **Deployers must put an authenticating front door (AgentCore Runtime inbound auth) in front of the runtime that maps each caller to the assessments they may use.** Residual: accepted as a deployment responsibility.
- **[LOW] T002 — Contributor impersonation.** A contributor sets another persona's `contributor_id`. Component: `src/runtime.py`. Mitigation: contributor IDs are pseudonymous attribution only; derive them from the authenticated principal. Residual: accepted.

#### Tampering

- **[MEDIUM] T003 — Indirect prompt injection.** Instructions hidden in documents, AWS resource names or tags, or JSON payloads make the model save false answers. Components: Strands agent, `src/doc_reader.py`, `src/discovery.py`. Mitigation: scoring is deterministic; injected text can only add `customer_asserted` evidence, which never yields a technical `met`; the system prompt treats documents as data; an Amazon Bedrock Guardrail is supported. Residual: accepted. Configure a guardrail with prompt-attack filters for shared deployments.
- **[MEDIUM] T004 — A steered report path overwrites project files.** The model is steered to pass an `output_path` such as `README.md` or a source file. Component: `src/tools/write_html_report.py`, `src/tools/write_summary_report.py`. Mitigation: `_resolve_report_path()` in `src/tools/_common.py` resolves the path (including symlinks) and allows only `.html`/`.htm` or `.md` files inside `REPORTS_DIR` (default `reports/`); the check runs before any assessment work. Tested in `tests/unit/tools/`. Residual: mitigated.
- **[MEDIUM] T006 — Supply-chain compromise.** Mitigation: exact pins in `requirements.txt`, base image pinned by digest, non-root container user, clean dependency audit. Residual: accepted.
- **[LOW] T005 — Local session file edited between runs.** Mitigation: atomic, locked writes; v1 runs on a single trusted workstation. Residual: mitigated.

#### Repudiation

- **[LOW] T007 — A contributor denies changing an answer.** Mitigation: v2 events are append-only and carry contributor ID and timestamp. Stronger attribution needs the authenticated front door. Residual: accepted.

#### Information disclosure

- **[HIGH] T009 — Document reader path traversal.** Mitigation: paths are resolved (including symlinks) and must stay inside `DOCUMENTS_DIR`; 2 MB and 50,000-character caps; the reader is removed from the AgentCore Runtime profile (`src/runtime.py`). Tested in `tests/unit/test_doc_reader.py`. Residual: mitigated.
- **[MEDIUM] T008 — Identifiers in reports or session files.** Mitigation: the `Redactor` removes account IDs, ARNs, emails, access keys, and secrets before persistence and rendering. Residual: mitigated.
- **[MEDIUM] T010 — Script injection into the HTML report.** Mitigation: every dynamic value is HTML-escaped; verified with script and image-handler payloads. Residual: mitigated.
- **[LOW] T011 — Content leaked through logs.** Mitigation: logs record identifiers, durations, and error types only. Residual: mitigated.

#### Denial of service

- **[MEDIUM] T012 — Oversized input or runaway model output.** Mitigation: `MAX_INPUT_JSON_BYTES` is checked before parsing and `BEDROCK_MAX_TOKENS` caps output. Residual: mitigated.
- **[LOW] T013 — Throttling during discovery.** Mitigation: bounded retries, staged discovery, and errors degrade to `unknown` evidence. Residual: mitigated.

#### Elevation of privilege

- **[HIGH] T014 — Prompt injection driving changes to customer resources.** Mitigation: the code contains no mutating AWS calls, so even an over-privileged role cannot be used to change resources through the agent. Grant only the read-only actions listed in `src/discovery.py`. Residual: mitigated.
- **[LOW] T015 — Unauthenticated local MCP server.** Mitigation: stdio transport only, and the single tool is the side-effect-free scorer. Residual: mitigated.

### Deployment assumptions

The ratings above assume the deployer does the following. [`docs/deployment-security.md`](docs/deployment-security.md) has an example for each.

1. Authenticates callers and enforces assessment membership before the runtime handler (T001, T002, T007).
2. Configures a tested, versioned Amazon Bedrock Guardrail for shared or public deployments (T003). Example: [`docs/examples/guardrail.json`](docs/examples/guardrail.json).
3. Grants discovery only the read-only actions in `MINIMUM_READ_ONLY_ACTIONS` / `ENHANCED_READ_ONLY_ACTIONS` (T014). Ready-made policies: [`docs/iam/`](docs/iam/).
4. Provisions AgentCore Memory with encryption at rest, an event-retention period that matches the assessment lifecycle, and a runtime role scoped to that resource.

## Data handling

- Do not provide credentials, secrets, tokens, private keys, personal data, or confidential customer data in prompts.
- The `Redactor` removes common account IDs, ARNs, email addresses, access keys, and key/value secrets before persistence and report rendering. It is a defense-in-depth control, not a substitute for correct data classification.
- Fixtures and demo inputs must remain synthetic. Generated reports, local sessions, caches, and virtual environments are ignored by Git.
- Review every generated report before sharing it externally because architecture and maturity observations can still be sensitive even after identifier redaction.

## Amazon Bedrock Guardrails and Responsible AI

The model is used only as a conversational wrapper. Deterministic Python owns all control statuses, scores, confidence, coverage, recommendations, and engagement routing.

For a public deployment:

1. Create and test a versioned Amazon Bedrock Guardrail appropriate to the organization’s content, privacy, and prompt-injection policies.
2. Configure `BEDROCK_GUARDRAIL_ID` and `BEDROCK_GUARDRAIL_VERSION` together. The application validates the pair and enables trace, input redaction, and output redaction in the Strands Amazon Bedrock model integration.
3. Test the guardrail against expected customer prompts and false-positive scenarios before deployment.
4. Keep customer assertions, observed AWS signals, reviewed evidence, and unknowns visibly distinct in reports. The LLM must never promote an assertion into a technical `met` result.

The repository does not send customer content to third-party model providers. The configured model provider is Amazon Bedrock.

## Dependencies and release controls

- `requirements.txt` contains exact tested runtime pins.
- Run the full test suite, type checks, secret scan, content security scan, and release artifact inspection before publication.
- Do not publish generated reports, session data, `.env` files, credentials, private account/resource identifiers, caches, or local logs.
- Do not use a whole-workspace archive for a public release; package only allowlisted source, dependency manifests, README, LICENSE, SECURITY.md, and approved sample assets.

## Reporting a security concern

If you discover a potential security issue in this project, notify AWS/Amazon Security via the [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/). Do not include vulnerabilities, customer data, credentials, or exploit details in public GitHub issues.
