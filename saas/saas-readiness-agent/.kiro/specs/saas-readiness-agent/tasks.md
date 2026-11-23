# SaaS Readiness Agent — Tasks

Delivered capabilities, grouped by area. New work goes here as unchecked
tasks and is checked off when it ships.

## Assessment and scoring

- [x] Seven-dimension rubric with 39 source-backed controls and public AWS references.
- [x] Deterministic scoring, confidence, maturity gates, and recommendations.
- [x] Evidence precedence; customer assertions never produce technical `met`.
- [x] Coverage model with provisional/baseline status at 70%.

## Evidence gathering

- [x] Two-stage read-only AWS discovery with graceful degradation and bounded retries.
- [x] Document reader confined to `DOCUMENTS_DIR`; removed from the hosted runtime.

## Questions

- [x] 14-topic `AQ-*` catalog mapped to canonical `BQ-*` signals.
- [x] Essential and full question modes; unknown modes rejected.
- [x] Skip already-answered questions; rank by weak controls.

## Reports

- [x] HTML and Markdown front-door reports with appendix; JSON outputs additive only.
- [x] Report writers confined to `.html`/`.md` files in `REPORTS_DIR`.

## Session profiles

- [x] Centralized, validated v1/v2 configuration.
- [x] v1 local JSON store with locked, atomic writes.
- [x] v2 AgentCore Memory answer events and Strands session-manager history.
- [x] Shared assessment identity; multi-persona resume across processes.
- [x] Answer save with bounded visibility confirmation.

## Runtime and packaging

- [x] Local REPL and Amazon Bedrock AgentCore Runtime entrypoint.
- [x] Optional stdio MCP server over the scorer.
- [x] One module per tool in `src/tools/`; structured JSON logging.
- [x] Non-root, digest-pinned container image with health check.

## Security

- [x] Redaction, input and output limits, safe identifiers, optional guardrail.
- [x] Least-privilege discovery IAM policies generated from the code and tested against every discovery call.
- [x] Deployment examples for inbound authentication and an Amazon Bedrock Guardrail.
- [x] STRIDE threat model; summary and deployment assumptions in `SECURITY.md`.

## Validation

- [x] Unit tests per tool; no real model or AWS calls in tests; 80% coverage gate.
- [x] Live v1 and v2 walkthroughs, including two-persona resume via AgentCore Memory.

## Open

- [ ] Unit tests for `AgentCoreMemorySessionStore` against a fake Memory client.
- [ ] Integration test of the agent loop with a mocked model.
- [ ] Split `src/assessment_core.py` into smaller modules.
