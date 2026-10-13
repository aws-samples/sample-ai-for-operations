# Amazon Bedrock Permissions Audit — Tasks

High-level capability checklist for the whole solution. A checked box means the work is built and
its automated tests pass. Phase 9 items are checks against a real non-production AWS account.

This solution is a deterministic CLI, not an agent. Build sub-phases that only apply to agents
(system prompt, Amazon Bedrock Guardrails, tool risk classification for an LLM) are **not
applicable**; do not block on them.

## Phase 1 — Foundation

- [x] 1.1 Scaffold `src/bedrock_permissions_audit/`, `infra/`, `config/`, `tests/`, `pyproject.toml` (entry point `bedrock-audit`, dependency `boto3` only, Python 3.12 or later). MIT-0 headers on every Python file.
- [x] 1.2 `models.py`: `Credential`, `ActionResult`, `Principal`, `Finding`, `Account`, `AccountResult`, `RunSummary`, `Tier`.
- [x] 1.3 `config.py`: TOML loader and flag overrides, frozen dataclass; `config/audit.example.toml` (a test asserts it equals the defaults).
- [x] 1.4 `data/bedrock_regions.json`: 33 commercial Regions, sample models and inference profiles; `--bedrock-regions` override.
- [x] 1.5 Structured JSON logging to stderr with redaction; tests assert no key ID or API key survives.

## Phase 2 — Account discovery

- [x] 2.1 `accounts.py`: `GetCallerIdentity`, Mode A, Mode B, `auto` fallback with notice, adaptive retries.
- [x] 2.2 Failed role assumption becomes a failed account; run continues (E1, E2).
- [x] 2.3 `runner.py`: bounded thread pool, completion-order callback.

## Phase 3 — Collectors (data retrieval)

- [x] 3.1 `collectors/credential_report.py`: generate, poll up to 60 seconds, parse; `CredentialReportTimeout`.
- [x] 3.2 `collectors/iam_users.py`: users, keys, exact last use, attached and group policies, root principal.
- [x] 3.3 `collectors/api_keys.py`: account-wide Amazon Bedrock API keys (any user), Claude Platform keys, orphan detection (E9, E10).

## Phase 4 — Evaluator

- [x] 4.1 `evaluator.py`: three passes, broad versus scoped, own-ARN escalation check, chunking, root modelled as allowed.
- [x] 4.2 `safe_evaluate`: transient failure becomes `unknown`; permission and credential errors fail the account.
- [x] 4.3 Rule-faithful fake simulator and `Stubber` response-shape tests (E8, E14).

## Phase 5 — Scoring (precision)

- [x] 5.1 `scoring/tiers.py`: all ten rules, boundary tests at exactly `N` days.
- [x] 5.2 `scoring/ordering.py`: sort key and visibility; dormant outranks active.
- [x] 5.3 `scoring/recommendations.py`: every branch, never a full key ID.
- [x] 5.4 End-to-end scenarios E3 to E12, E14, E15 through the real evaluator and scorer.
- [x] 5.5 Inactive access keys and API keys are rated as if re-enabled and reported as Low when that would be Critical or High, with `if_reactivated_tier` in the JSON and CSV, a Low sub-ordering, and a checkpoint format bump (scenario E17).
- [x] 5.6 Scoped-grant detection reads the resources the user's own policies name, and reports `unknown` when they are named but denied (scenario E18).
- [x] 5.7 The `bedrock:*` canary requires all of several unrelated management actions, checked against the real `AmazonBedrockLimitedAccess` document (scenario E19).

## Phase 6 — Output and checkpointing

- [x] 6.1 `output/terminal.py`: table, wrapped recommendations, summary, limitations, colour only on a terminal.
- [x] 6.2 `output/csv_writer.py`, `output/json_writer.py`: same findings in both; formula and control-character safe; keys masked.
- [x] 6.3 `output/remediation.py`: three policies as data with the `ReviewBeforeApplying` marker in each `Sid`; region and model policy written only when configured.
- [x] 6.4 `checkpoint.py`: per-account results, scoring fingerprint, `--resume` (E13).
- [x] 6.5 Exit codes 0, 2, 3; empty-account run writes valid empty outputs; owner-only files.

## Phase 7 — Infrastructure and permissions

- [x] 7.1 `infra/audit-role.yaml`: StackSet-ready read-only role. `cfn-lint` and `checkov` pass; the template carries `W28` and `W11` suppressions with reasons.
- [x] 7.2 `infra/caller-policy.json`.
- [x] 7.3 `tests/static/test_readonly.py` (E16): build gate.

## Phase 8 — Documentation

- [x] 8.1 `README.md`: purpose, related AWS capabilities, quick start, StackSet deployment, permissions, reading results (real example output), limitations, configuration table, handling output, license.
- [x] 8.2 `SECURITY.md`: threat model, limitations, data classification.
- [x] 8.3 `release-manifest.yaml`: `publish_domain: security`, `config` public, `pyproject.toml` and `SECURITY.md` in `public_paths`; the structure check passes.
- [x] 8.4 `--help` documents every setting or names it as file-only (a test checks parity with `config.py`).

## Phase 9 — Validation

- [x] 9.1 `pytest` with no AWS credentials passes; coverage above 90% on `scoring/` and `output/`; `ruff` clean; the wheel builds and the installed command runs in a clean environment.
- [x] 9.2 Mode B against a non-production account seeded with principals covering every tier, the escalation, deny, boundary and API-key cases. Results match expectations written before the run. Simulator action names are checked individually and the evaluator is checked against the real simulator.
- [x] 9.3 Mode A against a non-production organization: findings in member accounts are attributed correctly, failed role assumptions are reported with exit 0, `--resume` skips finished accounts, and the dedicated `infra/audit-role.yaml` role deployed by StackSet produces the same findings as an administrator role.
- [ ] 9.4 Mode A with `ExternalId`, and a real interrupt followed by `--resume`.
- [ ] 9.5 Timing run on a large organization. The README's advice on parallelism for several hundred accounts is an estimate until then.

## Verification summary

| Layer | Tool | Scope |
|---|---|---|
| Unit | `pytest` | config, models, logging, scoring, output, checkpoint, CLI |
| Collectors | `pytest` and `moto` | IAM fixtures, recorded edge cases |
| Evaluator | `pytest` with a rule-faithful fake and `Stubber` | scoped, broad, deny, boundary, response shapes |
| End to end | `pytest` fixture language, `moto` organization | E1 to E15, whole runs |
| Static gate | `pytest` | E16 read-only allowlist over `src/` and `infra/` |
| Infra lint | `cfn-lint`, `checkov` | `infra/audit-role.yaml` |

## Hard boundaries (build gates)

* No AWS call outside the design section 6 allowlist; E16 must pass before any commit.
* No LLM dependency in `pyproject.toml`.
* No file written outside the output directory.
* Remediation documents carry the `ReviewBeforeApplying` marker.

## Success criterion for hand-off to release

Requirements section 10 and design section 12 hold, and the master spec reflects what was built. The
open items above (9.4 and 9.5) need a real AWS account.
