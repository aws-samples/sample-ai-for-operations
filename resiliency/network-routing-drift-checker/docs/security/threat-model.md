# Threat model: Network Routing Drift Checker v1

Input for the release security review (tasks.md 4.4). Scope: the checker stack, the optional
cross-account link stack, the DevOps Agent skill, and the deploy scripts. As of 2026-10-16.

**Superseded by `SECURITY.md`** at the repository root, which is the actively-maintained,
reviewer-facing threat model (verified against the code, STRIDE-categorized, with a HIGH-severity
gate). This file is kept as the historical input `SECURITY.md` was generated from on 2026-10-16;
it is not updated line-by-line after that date. The pre-release security review flagged that this file's closing
section below was stale by the time of review — corrected here, but treat `SECURITY.md` as the
source of truth for current threat status going forward.

## System and trust boundaries

```
Networking account (N)                                   Agent Space account (D, optional, may equal N)
┌────────────────────────────────────────────────┐       ┌──────────────────────────────────────┐
│ Scheduler ─► Step Functions ─► Lambdas          │       │ AWS DevOps Agent Agent Space          │
│   read-only APIs: EC2/TGW, Network Manager,     │ HTTPS │   generic webhook (HMAC)              │
│   Direct Connect, VPN                           │──────►│   investigation (LLM) under its own   │
│   own data: S3 (intent, runs), DynamoDB, SNS    │       │   role; reads N via a secondary role  │
│   investigate ─ HMAC secret from SSM ───────────┘       │                                       │
│   callback ◄── aws.aidevops events ─────────────────────┤ EventBridge rule (link stack)         │
│      └─ sts:AssumeRole ─────────────────────────────────► journal-reader role (link stack)     │
└────────────────────────────────────────────────┘       └──────────────────────────────────────┘
        SNS e-mail ─► people (report text includes agent-written content)
```

Boundaries: (1) the checker and the customer's network, (2) the checker and DevOps Agent (data out
via webhook, data back via journal), (3) account N and account D, (4) the report and its readers.

## Assets

| Asset | Where | Sensitivity |
|---|---|---|
| Network topology and routing state (snapshots, findings) | S3 `runs/` (30 days), DynamoDB | Internal: reveals network design |
| Intent file (intended design) | S3 `intent/`, versioned | Internal; integrity matters: it decides what is drift |
| HMAC webhook secret | SSM SecureString in N | Secret |
| Step Functions task tokens | DynamoDB `TOKEN#` items (TTL) | Secret-like: completes a waiting task |
| Report | SNS subscribers | Internal |

## Threats and mitigations

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | The checker changes the customer's network | Every customer-facing action is `Describe`/`Get`/`List`/`Search`; no managed policies; deny-by-default IAM lint with a blocked-action list on both templates | `tests/iam/test_iam_lint.py`, `docs/security/iam-report.md` |
| T2 | An LLM decides what is drift (hallucinated or suppressed drift) | Drift is decided by deterministic code before any hand-off; the agent only explains NEW findings | Golden tests `tests/unit/test_golden.py`, check fixtures |
| T3 | The agent's output carries a mutating command into the report | `validation_commands` must match `^aws <svc> (describe\|get\|list\|search)-` and contain no `;`, `&&`, `\|`; anything else rejects the whole batch (`SCHEMA_INVALID`) and the report falls back to raw findings | `tests/unit/test_investigation.py`, `tests/unit/test_skill_package.py` |
| T4 | Prompt injection through finding text (tag values, names in `context`) steering the agent | Findings reach the agent as structured text it is told to investigate, not instructions; its output is validated against a strict schema scoped to the batch's finding IDs; scores and order are recomputed by code; links are accepted only inside the same Agent Space web app (`_trusted_url`); nothing from the agent is executed | `validate_result`, `normalize`, `test_investigation_url_must_point_into_the_agent_space` |
| T5 | Webhook secret leaks | Read from SSM at run time only; never in env vars, Step Functions state or S3; on the logger redaction list with the URL and task tokens | `tests/unit/handlers/test_investigate.py::test_secret_and_url_never_in_logs_returns_errors_artifacts_or_env`, `tests/unit/test_logging_util.py` |
| T6 | A forged event completes or fails a waiting task | No inbound endpoint (synth test). Same account: only AWS can emit `aws.*` sources; rule filtered to one Agent Space ID. In all shapes the callback re-reads the investigation from the Agent Space journal and acts only when its first message carries an `nrdc-` tag matching a live `TOKEN#` | `tests/iam/test_template.py::test_zero_ingress`, `tests/unit/handlers/test_callback.py` |
| T7 | Callback role completes tasks of other state machines | `states:SendTask*` scoped to the checker's state machine ARN; verified live 2026-10-15 | design §7.2, §14 item 5 |
| T8 | Cross-account role abuse | Journal reader: trust pinned with `aws:PrincipalArn` = the callback role; permission only `ListJournalRecords` on one Agent Space. Forwarder: trust `events.amazonaws.com` with `aws:SourceAccount` and `aws:SourceArn` = the one rule; permission only `InvokeFunction` on the callback. Callback's invoke grant (fixed 2026-10-18): `AWS::Lambda::ResourcePolicy` pinned with `aws:PrincipalArn` = the forwarder role's deterministic ARN, not a bare account principal. `deploy.sh` probes all three sides, fail-closed | `tests/iam/test_template.py` (link stack tests; `test_cross_account_permission_is_scoped_to_the_forwarder_role`), design §3.3a |
| T9 | Data leaves the account | Only NEW findings (IDs, kinds, resource IDs, prefixes, tag values, messages) go to the customer's own Agent Space, only when enabled; HTTPS only, URL pattern-checked (Bandit B310 posture) | `tests/unit/test_webhook.py` |
| T10 | Tampered intent file hides drift | Bucket is private, KMS-encrypted, versioned, TLS-only; the run manifest records the intent version used; the report says when the file is absent or rejected | `tests/unit/test_intent.py` |
| T11 | Silent failure reads as "no drift" | A clean day always sends a heartbeat; failed or missed runs raise alarms to the same topic; partial evaluation is never reported as clean | `tests/unit/test_evaluate_report.py`, operational tests |
| T12 | Data at rest exposure | One customer-managed KMS key (rotation on) for S3, DynamoDB, SNS and the DLQ; PITR on the table | `tests/iam/test_template.py` |

## Residual risks (accepted for a prototype, documented in the README)

1. **(Fixed 2026-10-18, was residual risk 1):** the cross-account callback permission used to name
   account D as a bare principal, not the forwarder role ARN, because the legacy
   `AWS::Lambda::Permission` mechanism's `SourceArn`/`SourceAccount` conditions only apply to AWS
   service principals invoking on behalf of their own resource, not a direct cross-account IAM
   caller. Fixed by switching to `AWS::Lambda::ResourcePolicy` (CDK `lambda.CfnResourcePolicy`),
   which supports the full IAM condition-key range, and pinning the grant to the forwarder role's
   deterministic ARN via `aws:PrincipalArn` — the same technique the journal-reader role's trust
   already used the other direction. See `SECURITY.md` T8 for the verified fix.
2. **Agent-written free text** (title, hypothesis, evidence observations) is shown in the report.
   It's validated for shape and length, not meaning. It's clearly labelled as the investigation's
   output, and the link goes only into the customer's own Agent Space.
3. **DevOps Agent's own mitigation step** may propose changes inside the Agent Space (seen once
   without the skill). The checker never executes anything, the skill forbids change plans for
   `nrdc-` incidents, and the Agent Space's role in N is read-only.
4. **Anyone in N who can write the bucket's `intent/` prefix can change what counts as drift.**
   Restrict `s3:PutObject` on it to the network team (README note recommended).
5. **Investigation evals deferred to post-v1** (user decision 2026-10-16, requirements §11.5): grouping quality is unscored. This is a usefulness risk, not a safety risk; the safety-relevant properties are enforced by code (T3, T4).

## For the release sanitization pass

As of 2026-10-16: real lab identifiers remained only in the master spec's verification notes
(`.kiro/specs/network-routing-drift-checker/design.md` and `tasks.md`); source, tests, README and
the skill contained none. **Corrected 2026-10-19 (pre-release security review):** this is no longer accurate as
a standing claim — the two lab account IDs were replaced with generic "two separate AWS accounts"
wording in both `design.md` and `tasks.md` as part of the sanitization pass for the
`public-release/v1.0.0` branch, and `main`'s copies were corrected the same way. Recorded fixtures
under `tests/fixtures/recorded/` were sanitized at recording time (`scripts/sanitize.py`).
