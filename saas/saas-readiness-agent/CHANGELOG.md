# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Release tags match
the `version` in `pyproject.toml`. Releases before 0.3.0 were tagged 0.0.x.

## [0.3.5] - 2026-11-23

### Changed
- License switched back to MIT-0 (MIT No Attribution) to match the aws-samples repository this sample is published in. `LICENSE`, `pyproject.toml`, the README, and every file header now say MIT-0.

## [0.3.4] - 2026-11-23

### Added
- Least-privilege IAM policies for AWS discovery in `docs/iam/`, generated from `MINIMUM_READ_ONLY_ACTIONS` / `ENHANCED_READ_ONLY_ACTIONS` by `src/iam_policies.py`. A test fails if they drift from the code or include a non-read-only action.
- `docs/deployment-security.md` with example AgentCore Runtime inbound authentication, assessment-membership options, and an Amazon Bedrock Guardrail (`docs/examples/guardrail.json`).

### Fixed
- AWS discovery called four read-only APIs that were missing from the declared action lists (`bedrock-agentcore:ListAgentRuntimes`, `bedrock-agentcore:ListGateways`, `s3vectors:ListVectorBuckets`, `s3vectors:ListIndexes`), so a policy built from the lists would deny them.
- Project URLs in `pyproject.toml` now point to `aws-samples/sample-ai-agents-for-operations`.
- Removed a stale reference to `requirements-aws.txt` in `src/discovery.py`.

### Changed
- `SECURITY.md` shows residual ratings for the three High threats.

## [0.3.3] - 2026-11-16

### Changed
- Replaced the two feature specs with one master specification in `.kiro/specs/saas-readiness-agent/` (requirements, design, tasks), updated to match the current code.
- The detailed threat model is no longer part of the published sample; `SECURITY.md` keeps the STRIDE summary, findings, and deployment assumptions.

## [0.3.2] - 2026-11-16

### Security
- `write_html_report` and `write_summary_report` now write only `.html`/`.htm` or `.md` files inside `REPORTS_DIR` (default `reports/`). Before, a model-steered `output_path` could overwrite any file inside the working directory, such as `README.md` or source files.

### Added
- STRIDE threat model and a threat-model summary in `SECURITY.md`.
- `REPORTS_DIR` setting.

## [0.3.1] - 2026-11-16

### Fixed
- Local (v1) session store no longer crashes or loses answers when several answers are saved at the same time, for example when the model saves two or three answers in one turn. Writes now hold a lock across the read-modify-write cycle and use a unique temporary file per write.

## [0.3.0] - 2026-11-16

### Changed
- Moved each agent tool into its own module under `src/tools/`. `src/agent.py` now only wires the tools, system prompt, and model.
- Moved tests to `tests/unit/`, with one test file per tool in `tests/unit/tools/`.
- Container image now has a `HEALTHCHECK` and pins the base image by digest.
- Re-raised runtime errors are logged at WARNING.

### Added
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and this changelog.
- Requirements and design specs.

## [0.0.4]

### Changed
- `get_assessment_questions` rejects unknown modes. `all` is accepted as an alias of `full`.
- Narrative explainer failures are reported instead of silently dropped.
- The model ID is read from configuration everywhere.

## [0.0.3]

### Security
- `read_customer_document` reads only inside `DOCUMENTS_DIR` and is removed from the AgentCore Runtime profile.
- Upgraded `mcp` to 1.30.0.

### Fixed
- README installation steps (`pip install -e . --no-deps`).

## [0.0.2]

### Added
- Input size and output token limits, AWS SDK retries, a Dockerfile, structured JSON logging, and MCP server tests.

## [0.0.1]

### Added
- Initial release: deterministic SaaS readiness scoring, read-only AWS discovery, local and AgentCore Memory session profiles, and HTML/Markdown/JSON reports.
