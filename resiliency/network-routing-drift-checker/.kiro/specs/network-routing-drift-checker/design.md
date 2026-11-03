# Network Routing Drift Checker — Design

**Status:** Approved in Ideation; reconciled with the as-built v1 on 2026-10-16 (tasks.md 4.3). "As built" and "Verified" notes record where the build refined the approved design.
**Pattern:** #9c — AWS DevOps Agent as investigation engine, headless (Variant A: event-driven)
**Implements:** `requirements.md` in this directory. Section references (§) point there unless marked "this doc."

---

## 1. Architecture

```
EventBridge Scheduler (cron + timezone)            manual StartExecution (ad hoc)
        │                                                   │
        └──────────────► AWS Step Functions (Standard) ◄────┘
                               │
   ┌───────────────────────────┼──────────────────────────────────────────┐
   │ 1 Init            Lambda: load config, fetch + validate intent file, │
   │                   discover Regions (DescribeRegions enabled only,    │
   │                   Cloud WAN edge locations, TGW/DXGW presence)       │
   │ 2 Collect         Map state, MaxConcurrency=N, one branch per Region │
   │                   Lambda: Describe/Get/List → snapshot JSON → S3     │
   │                   (Cloud WAN collected once, us-west-2 endpoint)     │
   │                   per-branch Catch → "Region not evaluated"          │
   │ 3 Evaluate        Lambda: six deterministic checks over snapshots    │
   │                   → findings[] with deterministic IDs                │
   │ 4 Diff            Lambda: DynamoDB state → NEW / KNOWN / RESOLVED    │
   │ 5 Choice          NEW findings > 0 AND handoff enabled?              │
   │     yes ─► 6 Investigate  Lambda (.waitForTaskToken, Timeout,        │
   │                   Heartbeat): HMAC-sign, POST to DevOps Agent        │
   │                   webhook, store task token keyed by incidentId      │
   │                   ◄── EventBridge rule (source aws.aidevops,         │
   │                       Investigation Completed/Failed/…) ─► Callback  │
   │                       Lambda: ListJournalRecords, correlate tag,     │
   │                       parse result, SendTaskSuccess / Failure        │
   │                   Catch(States.Timeout | States.TaskFailed |         │
   │                         WebhookError) ─► fallback flag               │
   │     no  ─► skip                                                      │
   │ 7 Report          Lambda: compose heartbeat or drift report          │
   │ 8 Publish         SNS:Publish (one topic)                            │
   │ 9 Marker          DynamoDB: update last-successful-full-scope-run    │
   │                   (only when scope was full, §9.2)                   │
   └──────────────────────────────────────────────────────────────────────┘
                               │ on execution failure / missed schedule
                    CloudWatch alarms ──► same SNS topic
```

Everything inside the box is the checker the customer deploys. DevOps Agent is outside it: a service the customer already runs, reached through one webhook, returning through one callback.

### 1.1 Runtime choices (per `tech.md`)

| Component | Choice | Why |
|---|---|---|
| Orchestration | AWS Step Functions Standard | `waitForTaskToken` with timeout + heartbeat; Map fan-out with concurrency cap; execution history is the run log |
| Compute | AWS Lambda, Python 3.12, arm64, 512 MB default | Pay per run; a daily run is ~15 invocations |
| Scheduler | EventBridge Scheduler | Native timezone support (DST-safe), unlike EventBridge rules |
| State | DynamoDB on-demand, PITR on | Finding history, last-run marker, task-token map |
| Intent + snapshots + reports | S3, versioned, SSE-KMS with the stack's customer-managed key (§11), block public access | Intent audit trail for free; snapshots retained 30 days by lifecycle |
| Secrets | SSM Parameter Store SecureString | HMAC signing secret, read at runtime |
| Delivery | SNS, one topic, encrypted | §10 |
| IaC | AWS CDK v2 (TypeScript), one `cdk deploy`, one `cdk destroy` | §14.5 |
| Investigation | AWS DevOps Agent via generic HMAC webhook | §11 |

No containers, no VPC, no NAT: every Lambda talks only to AWS service endpoints and (one of them) the DevOps Agent webhook URL over HTTPS.

## 2. Components

### 2.1 Lambda functions

| Function | Role | Reads | Writes |
|---|---|---|---|
| `init` | Load config; fetch + validate intent file; discover Regions; emit run manifest | S3 intent key, `ec2:DescribeRegions`, Network Manager (core network + policy), TGW/DXGW presence per Region | S3 `runs/<run-id>/manifest.json` |
| `collect-cloudwan` | One invocation against the global Network Manager endpoint (us-west-2): policy (`Alias=LIVE`), attachments, CNE routes per segment × edge | Network Manager | S3 `runs/<run-id>/cloudwan.json` |
| `collect-region` | One invocation per Region (Map): TGWs, route tables, attachments, associations, propagations, routes, DX VIFs, DXGW associations | EC2, Direct Connect | S3 `runs/<run-id>/<region>.json` |
| `evaluate` | Six checks over all snapshots; deterministic IDs | S3 snapshots + manifest | S3 `runs/<run-id>/findings.json` |
| `diff` | NEW / KNOWN / RESOLVED against drift-state table | DynamoDB | DynamoDB finding items; S3 `runs/<run-id>/diff.json` |
| `investigate` | Build investigation payload(s), HMAC-sign, POST; persist task token | SSM SecureString, S3 diff | DynamoDB `TOKEN#` items; HTTPS POST to webhook |
| `batch-findings` | Split NEW drift findings into investigation batches (§6.1) | S3 diff + manifest | S3 `runs/<run-id>/investigation-batches.json` |
| `callback` | Correlate an `aws.aidevops` event, read the result from the journal (assuming the journal-reader role cross-account), validate it batch-scoped, `SendTaskSuccess`/`Failure`/`Heartbeat` | DynamoDB `TOKEN#`; `ListJournalRecords` | Step Functions; DynamoDB `TOKEN#`; S3 `runs/<run-id>/investigation-<batch>.json` |
| `merge-investigations` | Merge per-batch results, check the run-level invariant, rank across batches | S3 per-batch results; DynamoDB `TOKEN#` | S3 `runs/<run-id>/investigation.json`; `InvestigationFailed` metric |
| `report` | Compose heartbeat or drift message | S3 run artifacts | S3 `runs/<run-id>/report.txt`; returns message to the state machine |

All functions share one layer (`drift_core`) that holds the schema, the check implementations, the ID derivation and the report formatter, so the fixture tests exercise exactly the code that runs in Lambda.

### 2.2 Repository layout (per `structure` steering)

```
network-routing-drift-checker/
├── src/
│   ├── config.py                   # every env var read here, nowhere else
│   ├── handlers/                   # one thin Lambda handler per function above
│   ├── drift_core/
│   │   ├── intent.py               # schema + validator (§7.2)
│   │   ├── collectors/             # cloudwan.py, tgw.py, directconnect.py — data retrieval
│   │   ├── checks/                 # check1_domain.py … check6_hybrid_path.py — precision
│   │   ├── finding.py              # Finding model + deterministic ID (this doc §5)
│   │   ├── diff.py                 # NEW/KNOWN/RESOLVED — precision
│   │   ├── limits.py               # check 5 limit registry (this doc §4.5)
│   │   ├── report.py               # message composer — precision
│   │   └── webhook.py              # HMAC signing + payload split
│   └── prompts/                    # none: the only LLM is DevOps Agent, instructed by the skill
├── devops-agent-skill/
│   └── network-routing-drift/      # SKILL.md, references/, evals/, packaged .zip
├── infra/                          # CDK app (TypeScript): one stack
├── tests/
│   ├── fixtures/                   # recorded API responses per check × drift/no-drift × edge cases
│   ├── unit/                       # checks, ID derivation, diff, intent validator, report, HMAC
│   ├── iam/                        # deny-by-default policy lint (this doc §7)
│   └── evals/                      # investigation eval harness + recorded finding sets
├── scripts/                        # deploy.sh, destroy.sh, smoke-test.sh, upload-intent.sh
└── README.md
```

## 3. Data flow and state machine

### 3.1 Run manifest (output of `init`)

```json
{
  "run_id": "2026-10-13T05:00:00Z-a1b2c3",
  "scope": "full" | "partial",
  "regions": {"evaluate": ["eu-central-1", "eu-west-1"], "excluded": [], "source": "discovered" | "allowlist" | "override"},
  "cloudwan": {"core_network_id": "core-network-0abc", "home_region": "us-west-2", "edge_locations": ["eu-central-1", "eu-west-1"]} | null,
  "intent": {"status": "ok" | "absent" | "rejected", "version_id": "s3-version", "errors": []},
  "lookback_from": "2026-05-11T05:00:12Z",
  "thresholds": {...}, "tag_key": "Environment", "concurrency": 4
}
```

`scope` is `full` only when no execution-input override touched Regions or lookback; only full-scope runs move the marker (§9.2).

### 3.2 State machine definition (shape)

```
Init ─► CollectCloudWan (skip if manifest.cloudwan == null)
     ─► CollectRegions  [Map, ItemsPath=$.regions.evaluate, MaxConcurrency=$.concurrency]
            └─ CollectRegion  Retry: CollectionThrottled | Sandbox.Timedout ×5, backoff 2.0, max 60 s
                              (errors classified in collectors/errors.py; access denied and other
                               API errors are NOT retried. Verified live 2026-10-13)
                              Catch: States.ALL ─► RecordRegionNotEvaluated (Pass) ─► continue
     ─► Evaluate ─► Diff
     ─► HasNewAndHandoff? (Choice: $.diff.new_drift > 0 AND $.init.handoff_enabled)
            yes ─► BatchFindings (Lambda: split NEW drift findings into batches per 6.1,
                                  ≤ MaxFindingsPerInvestigation, ≤ 12 KB description,
                                  resource-affine grouping; writes investigation-batches.json)
                ─► InvestigateBatches [Map, ItemsPath=$.batches.batches,
                                       MaxConcurrency=InvestigationConcurrency (default 2)]
                      └─ InvestigateBatch [Type=Task, Resource=lambda:invoke.waitForTaskToken,
                                       TimeoutSeconds=InvestigationTimeoutSeconds (default 2700),
                                       HeartbeatSeconds=InvestigationHeartbeatSeconds (default 2700)]
                                       ResultPath=$.result  (the callback's SendTaskSuccess output)
                         Retry: WebhookServerError | WebhookTimeout | WebhookTransportError ×2
                         Catch: States.ALL, ResultPath=$.error
                                ─► MarkBatchFailed (Pass) ─► end of this Map iteration
                                   (other iterations unaffected)
                ─► MergeInvestigations (Lambda: per-batch status "ok" | "failed:<reason>",
                                        run-level invariant, recomputed cross-batch ranking;
                                        writes investigation.json; emits InvestigationFailed
                                        = count of failed batches)
            no  ─► SkipInvestigation (Pass: {status: "skipped"})
     (both) ─► Report reads investigation.json when the hand-off ran
     ─► Report ─► Publish (sns:publish) ─► UpdateMarker (dynamodb:updateItem, only if scope == full)
```

**Partial failure across batches:** each Map iteration owns its own Catch, so a failed or timed-out batch never aborts the Map. `MergeInvestigations` keeps every successful batch's incidents and records the failed batches. The report lists, per batch, either the ranked incidents with the investigation link or the line "Investigation batch N failed: <reason>; raw findings follow" with that batch's NEW findings in full. A run where every batch fails degrades to the raw-findings message of §10.2 with the failure statement. A run where some batches fail is still published as a drift report, with the `InvestigationFailed` metric and alarm (this doc §9) covering the operational signal.

Retry/Catch on every Lambda task: transient errors retried ×3; terminal errors fail the execution (no SNS message from the run; the failed-execution alarm fires instead, §10.2).

### 3.3 Investigation callback path

The `investigate` function POSTs to the webhook and returns nothing to Step Functions directly; the execution pauses on the task token. The token is stored as `TOKEN#<incidentId>` in DynamoDB with a TTL slightly longer than `TimeoutSeconds`. The `callback` function receives the investigation result, looks up the token by `incidentId`, validates the result against the callback schema (this doc §6.3), and calls `SendTaskSuccess` (or `SendTaskFailure` with `SCHEMA_INVALID`).

**Verified (task 0.1, recorded 2026-10-13).** Sources: the reference implementation [`aws-samples/sample-proactive-health-event-impact-analyzer`](https://github.com/aws-samples/sample-proactive-health-event-impact-analyzer) (files `infrastructure/cdk/lambda/investigation-callback/index.ts`, `infrastructure/cdk/lib/constructs/investigation-workflow.ts`, read at `HEAD` via the GitHub API), the [DevOps Agent EventBridge events detail reference](https://docs.aws.amazon.com/devopsagent/latest/userguide/integrating-devops-agent-into-event-driven-applications-using-amazon-eventbridge-devops-agent-events-detail-reference.html), and the botocore `devops-agent` service model (boto3 1.43.111).

**Transport: Amazon EventBridge. Zero ingress.** DevOps Agent emits events with `source: aws.aidevops` to the default event bus **in the Agent Space's Region**. An EventBridge rule targets the `callback` Lambda. No HTTP endpoint is needed or created; the deployment gate is closed.

| Aspect | Verified behavior | Design consequence |
|---|---|---|
| Terminal events | `detail-type` ∈ `Investigation Completed`, `Investigation Failed`, `Investigation Timed Out`, `Investigation Cancelled` (the four the reference subscribes to) | Rule pattern matches these four, plus `Investigation Skipped` and `Investigation Linked` (documented, not handled by the reference). Skipped/Linked mean our batch will never complete, so `callback` fails the batch immediately with that reason instead of waiting out the timeout. |
| Event payload | `detail.metadata.{agent_space_id, task_id, execution_id}`, `detail.data.{status, priority, created_at, updated_at, summary_record_id}`. `execution_id` and `summary_record_id` are optional. **The event carries neither our `incidentId` nor the investigation text.** | Correlation and results both come from a follow-up API call (next two rows). An event without `execution_id` is ignored. |
| Correlation | The reference calls `ListJournalRecords(agentSpaceId, executionId, recordType="message", order=ASC)`, takes the first `user` message (the webhook text we sent), and extracts a `[INVESTIGATION_ID:<id>]` tag | The §6.2 description block **must** contain the literal tag `[INVESTIGATION_ID:nrdc-<run_id>-<batch_n>]` on its own line. `callback` extracts it and loads `TOKEN#<id>`. Events whose first message has no `nrdc-` tag belong to other investigations in the same Agent Space and are dropped silently. |
| Results | The reference reads the last `assistant` message. The events reference says the summary is a record of type `investigation_summary_md` whose `recordId` equals `summary_record_id` | `callback` reads the `investigation_summary_md` record first and falls back to the last assistant message. It extracts the fenced `nrdc-investigation/v1` JSON block (§6.3). Completed with no summary and no block → `SendTaskFailure(NO_RESULT)`. |
| API model | `ListJournalRecords` requires `agentSpaceId`, `executionId`; also accepts `limit`, `nextToken`, `recordType`, `order`. The current model uses `limit`; the reference passes `maxResults` | Use the current model's parameter names. Bundle the `devops-agent` client at the version that defines it, since the Lambda runtime may not include it. |
| Investigation link | `https://<agent_space_id>.aidevops.global.app.aws/investigation/<task_id>` (reference) | Used as `investigation_url` when the agent's block omits it. |
| IAM | `aidevops:ListJournalRecords` on `arn:aws:aidevops:<region>:<acct>:agentspace/*` (reference); `stateMachine.grantTaskResponse(callback)` | Scoped to the one Agent Space ARN via the new `DevOpsAgentSpaceId` parameter (§7.2, §8). For `SendTask*`, see §7.2. |
| Delivery reliability | The reference uses async-invoke retries plus an SQS DLQ with an alarm on the callback | Adopted: `callback` gets an async-invoke DLQ (SQS, KMS-encrypted) and a `CallbackDlqMessages ≥ 1` alarm to the topic (§9). |

**Region constraint (new, also in requirements §11.2 and §15):** events land in the Agent Space's Region. The stack must be deployed in that Region, or the rule never fires and every investigation times out. Check: the generic webhook URL has the form `https://event-ai.<region>.api.aws/webhook/generic/<id>` (webhook docs). When `EnableDevOpsAgentHandoff=true`, the CDK app parses `<region>` from `DevOpsAgentWebhookUrl` and fails synth if it differs from the stack Region or the URL doesn't match that form. The README documents the constraint. Cross-Region event forwarding is post-v1. The constraint also covers the cross-account shape (this doc §3.3a), because EventBridge sends events to targets in other accounts only [within the same Region](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-cross-account.html).

### 3.3a Cross-account hand-off (Agent Space in another account)

Decided 2026-10-14 (requirements §4, §11.1). Account **N** is the networking account: the checker stack and the evaluated network live there. Account **D** is the DevOps Agent account, which holds the Agent Space. Both are in the same Region. `DevOpsAgentAccountId` selects the shape. When it equals N (the default), everything in §3.3 applies unchanged and no companion stack exists.

```
Account N (checker)                                Account D (Agent Space)
───────────────────                                ───────────────────────
investigate ── HTTPS POST (HMAC) ───────────────►  generic webhook ► investigation
                                                         │ aws.aidevops events
                                                         ▼
callback ◄── direct cross-account Lambda target ──  default bus rule (companion stack)
   │         (execution role nrdc-event-forwarder-<N>-<region>)
   └─ sts:AssumeRole ────────────────────────────►  nrdc-journal-reader-<N>-<region>
                                                     aidevops:ListJournalRecords on the
                                                     one Agent Space ARN
Agent Space ◄─ secondary source: DevOps Agent assumes a role in N for the investigation
               reads (customer prerequisite, §15; task 3.8)
```

| Element | Where | What | Why this way |
|---|---|---|---|
| Event delivery | rule in D's default bus → `callback` in N | Same pattern and filter as §3.3 (`source`, `detail-type`, `agent_space_id`). The target is the `callback` function ARN in N, using EventBridge [cross-account targets](https://aws.amazon.com/blogs/compute/introducing-cross-account-targets-for-amazon-eventbridge-event-buses/) with an execution role in D. | One rule, no forwarding bus in N, no bus policy. Rejected: bus-to-bus forwarding, which needs a second rule plus a bus resource policy in N. |
| Execution role | D, `nrdc-event-forwarder-<N>-<region>` | Trust: `events.amazonaws.com` with `aws:SourceAccount` = D and `aws:SourceArn` = the rule ARN. Permission: `lambda:InvokeFunction` on the one `callback` ARN. | The source account must have an execution role. Its fixed name lets N's stack name it before it exists. |
| Callback resource policy | N | Allows `lambda:InvokeFunction` from account D, scoped to the exact forwarder-role ARN via `aws:PrincipalArn` (fixed 2026-10-18; see below). In D, only the execution role holds that permission on the callback ARN. | The target must explicitly allow the source (the blog above), scoped to the one role that should be able to invoke it, not the whole account. |
| Journal read | D, `nrdc-journal-reader-<N>-<region>` | Trust: N's account, with `aws:PrincipalArn` = the `callback` role ARN. Permission: `aidevops:ListJournalRecords` on `arn:aws:aidevops:<region>:<D>:agentspace/<DevOpsAgentSpaceId>`. | `ListJournalRecords` only works against the Agent Space's own account. A `PrincipalArn` condition on the account principal works even before the callback role exists, so deploy order doesn't matter. No external ID: both sides are the customer's own accounts and the principal is pinned (no third party, no confused deputy). |
| Callback code | N | When `DEVOPS_AGENT_ACCOUNT_ID` ≠ its own account: `sts:AssumeRole` into the journal reader, and cache the credentials for the invocation. The `devops-agent` client is created from those credentials. Nothing else changes. | Keeps one code path with one switch. |
| Webhook | N → D's webhook URL | Unchanged. The HMAC webhook doesn't depend on the caller's account. The secret stays in N's SSM. | — |
| Investigation reads | N | DevOps Agent assumes a secondary-source role in N, created by the customer from the console's trust policy. It has `AIDevOpsAgentAccessPolicy` plus the network/CloudTrail/Health additions from requirements §15 (task 3.8 snippet). | The trust policy is generated per Agent Space by the console, so the checker stack doesn't own this role. That keeps the checker's own roles free of investigation reads (this doc §7.1). |
| Stack | `NetworkRoutingDriftChecker-DevOpsAgentLink` in D, `infra/lib/devops-agent-link-stack.ts`, same CDK app | Parameters: `CheckerAccountId`, `CallbackFunctionArn`, `CallbackRoleArn`, `DevOpsAgentSpaceId`. Contents: the rule, the two roles, tags. No KMS, no data store. | — |
| Deploy order | `scripts/deploy.sh` | 1) Checker stack in N. 2) Read the `CallbackFunctionArn` / `CallbackRoleArn` outputs. 3) Companion stack in D with `DEVOPS_AGENT_PROFILE`. 4) Probe: assume the journal reader as the callback role would. A failed probe fails the deploy and prints which side is missing. `destroy.sh` removes D first, then N. | Fixed role names remove the circular dependency. Between steps 1 and 3, a hand-off would time out and fall back, which is safe. |

**As built (tasks.md 3.13, 2026-10-14):**

- **One template, three shapes.** CloudFormation conditions `HandoffEnabled`, `SameAccountHandoff` and `CrossAccountHandoff` (`DevOpsAgentAccountId` non-empty and ≠ `AWS::AccountId`). The four hand-off functions and the state machine branch always exist. Only the shape-specific grants (`ssm:GetParameter`; `aidevops:ListJournalRecords` or `sts:AssumeRole`), the same-account rule and the two Lambda permissions are conditional. The state machine's Choice reads `handoff_enabled` from `init`, so a disabled hand-off never enters the branch.
- **Callback resource policy, cross-account (fixed 2026-10-18, pre-release security scan HIGH finding):** an
  `AWS::Lambda::ResourcePolicy` (not the legacy `AWS::Lambda::Permission`) whose single statement
  grants `lambda:InvokeFunction` to account D's root principal, scoped by `ArnEquals
  aws:PrincipalArn` = the forwarder role's deterministic ARN
  (`nrdc-event-forwarder-<N>-<region>`). Originally built with a bare account-D principal and no
  further scoping, because `AWS::Lambda::Permission`'s `SourceArn`/`SourceAccount` condition keys
  only apply when an AWS *service* principal is the caller, not a direct cross-account IAM role —
  so there was no way to name the exact role with the legacy mechanism before it existed.
  `AWS::Lambda::ResourcePolicy` supports the full IAM condition-key range on a complete policy
  document, so the same "name the ARN before the role exists" trick already used for the
  journal-reader ARN (just below) works here too. The two resource types are never combined on the
  same function for the same condition (CloudFormation docs warn mixing them can silently overwrite
  statements): `SameAccountHandoff` keeps `AWS::Lambda::Permission`, `CrossAccountHandoff` now uses
  `AWS::Lambda::ResourcePolicy`. Inside D, only the forwarder role holds `lambda:InvokeFunction` on
  the callback ARN. Item 6 still checks live whether delivery works this way.
- **Forwarder trust:** `events.amazonaws.com` with `aws:SourceAccount` = D and `aws:SourceArn` = the rule ARN. The rule has a fixed name (`nrdc-devops-agent-investigation-events`), so the ARN is known without a circular reference.
- **Journal reader trust:** account N, with `ArnEquals aws:PrincipalArn` = the `CallbackRoleArn` parameter.
- **`deploy.sh` probe** (the deployer isn't the callback role, so it can't assume the reader): both roles exist in D; the reader trusts the callback role ARN; the callback's resource policy names D; `iam:SimulatePrincipalPolicy` allows `sts:AssumeRole` for the callback role. Any miss fails the deploy.

**Verify in build (task 3.13, also this doc §14 items 6–7):**

- whether the Lambda resource policy needs the execution role ARN as the principal (as the blog says) or D's account principal;
- whether `aws.aidevops` events reach a cross-account target the same way they reach a same-account one;
- which of the requirements §15 reads `AIDevOpsAgentAccessPolicy` already covers in the secondary account.

**Live run, 2026-10-15 (task 3.14, first attempt).** One NEW finding, one batch. The webhook returned 200. The investigation took **16.4 minutes** in DevOps Agent, so the 900-second batch timeout cut it off. The run still succeeded: raw-findings report, `failed:timeout-running` (because `started_at` had been set), and `InvestigationFailed` went to ALARM. The late `Completed` event was dropped as "no live TOKEN#", as designed. Two things learned:

- **The timeout was too short.** Defaults raised to `InvestigationTimeoutSeconds` = `InvestigationHeartbeatSeconds` = 2700 (45 min, about 2.7× the measured duration), and the state machine backstop to 4 h.
- **`Investigation Created` arrives before the webhook message is in the journal**, so the callback can't correlate it and drops it. That's harmless: `In Progress` follows about 15 s later and sets `started_at`.

**Live run, 2026-10-15 (second attempt, with the skill uploaded).** One NEW finding (`hybrid-path-prefix-not-found`, `172.30.0.0/16`). The investigation took about 12 minutes, and DevOps Agent ended with a valid `nrdc-investigation/v1` block. The callback validated it batch-scoped, recomputed the score, wrote `investigation-1.json` and called `SendTaskSuccess`. MergeInvestigations reported 1 ok batch, invariant ok. The content followed the contract:

- `confidence: low` with "No evidence found";
- `actor_identified: false`;
- five `state` evidence items;
- nine read-only validation commands;
- a `notes` field confirming CloudTrail had continuous coverage, so the missing event is real;
- "no mitigation change plan was produced".

Gap found: the drift report doesn't render the investigation yet (task 3.5).

### 3.4 Heartbeat during the wait, and what it cannot do

The `investigate` function returns immediately after the POST. From that moment the execution is paused on the task token and nothing in this solution is running. Heartbeats can only be sent by the `callback` function, and only when DevOps Agent delivers something to it.

**Verified (task 0.1): intermediate signals exist but are one-shot.** DevOps Agent also emits `Investigation Created`, `Investigation In Progress`, `Investigation Priority Updated` and `Investigation Pending Triage`. These mark state changes, not a periodic pulse. A short `HeartbeatSeconds` would therefore kill healthy investigations that are simply busy and silent after `In Progress`. **So a hung investigation is still detected only when `TimeoutSeconds` expires.** The one-shot events are still useful for the failure reason.

Consequences adopted in this design:

- `InvestigationTimeoutSeconds` defaults to **900** (15 minutes). The reference blog reports 2–10 minutes; the reference code waits up to 30. 15 minutes bounds the worst case without stalling the daily report. Configurable upward for large networks.
- `InvestigationHeartbeatSeconds` defaults equal to the timeout and stays there. `callback` calls `SendTaskHeartbeat` on `Created`/`In Progress`/`Priority Updated`, which is harmless and lets a customer who lowers the heartbeat catch "never acknowledged" sooner. The README explains the trade-off.
- `callback` records `started_at` on `TOKEN#<id>` when `In Progress` arrives. A timed-out batch can then be reported as `failed:timeout-never-started` (likely the webhook was dropped or the monthly investigation limit was hit) or `failed:timeout-running` (the investigation outran the timeout). That gives the reader something to act on.
- A timed-out batch is reported as `failed:timeout` (this doc §3.2), the `InvestigationFailed` metric increments, and the alarm `InvestigationFailed ≥ 1` (this doc §9) notifies the topic. The drift report itself also carries the line, so a reader of the daily message sees it without the alarm.
- The webhook returning 200 means "queued," not "investigating" (per the webhook docs). A 200 followed by silence is indistinguishable from a slow investigation until the timeout; the README's troubleshooting section says so and points to the Agent Space's monthly investigation limit as the first thing to check.

## 4. The checks (deterministic)

Each check is a pure function `(snapshots, manifest, intent) -> list[Finding]`. No network, no time dependency except through the manifest.

### 4.1 Check 1 — wrong routing domain

**Cloud WAN.** For each attachment in `ListAttachments` in state `AVAILABLE` or `UPDATING`: compute the segment the policy's `attachment-policies` would assign. Rules are evaluated in `rule-number` order and the first match wins. `condition-logic` may be `and` (the default) or `or`. The action is `association-method: constant | tag`. Compare the result with the attachment's `SegmentName`; a mismatch is `cloudwan-wrong-segment`. An attachment with `ProposedSegmentChange` pending is `cloudwan-segment-change-pending` (informational). An attachment matching no rule, or a `tag` method whose key is absent on the attachment, is `cloudwan-no-matching-rule` (informational).

Policy constructs evaluated vs. not evaluated (implemented in `drift_core/checks/cloudwan_policy.py`):

| Construct | Evaluated | Values |
|---|---|---|
| Condition types | Yes | `any`, `tag-exists`, `tag-value`, `resource-id`, `region` (edge location), `account-id`, `attachment-type` |
| Condition operators | Yes | `equals` (default), `not-equals`, `contains`, `begins-with` |
| Condition types | **No** | Anything else (e.g. condition types added to the policy language after v1) |
| Condition operators | **No** | Anything else |
| Action | **No** (skipped) | `add-to-network-function-group`: network function group attachments are out of scope for v1 (requirements §13, item 8) and produce no finding |

When a rule uses a construct that isn't evaluated, the attachment gets a `cloudwan-rule-not-evaluated` finding (severity `system`, carrying the rule number) and evaluation stops for that attachment. It is **never** treated as matching, as not matching, or as drift, so an unsupported construct can neither hide drift nor invent it.

**TGW.** For each attachment in `DescribeTransitGatewayAttachments` with an `Association` whose state is `associated`: read `Environment` tag on the attachment and on the associated route table (`DescribeTransitGatewayRouteTables`). Apply §6 rules. Mismatch → `tgw-wrong-route-table`. Missing tags → `untagged-attachment` / `untagged-route-table` (informational).

### 4.2 Check 2 — prefix leak

**Cloud WAN.** For each `(segment, edge)` route table from `GetNetworkRoutes`, check each route whose `Destinations[].SegmentName` ≠ the table's segment. The source segment must be permitted by the policy:

- a `segment-actions` entry with `action: share, mode: attachment-route` between the two segments (`share-with` may be `*`, a list, or `{except: [...]}`), **after** both segments' `deny-filter` / `allow-filter`. Per the [policy reference](https://docs.aws.amazon.com/network-manager/latest/cloudwan/cloudwan-policies-json.html), the filters are applied after sharing. A share that a filter blocks therefore does not permit the route;
- or a `STATIC` route declared by an `action: create-route` for that segment and CIDR.

Anything else is `cloudwan-prefix-leak`, carrying the offending prefix, source segment and attachment.

**Isolated segments** (`isolate-attachments: true`): the only routes available are shared routes and static routes. A `PROPAGATED` route to a **VPC** attachment in the same segment is therefore `cloudwan-isolation-leak`. Route-table (TGW) attachments are exempt from isolation per the same reference, and VPN and Connect attachments are not flagged in v1.

Not evaluated in v1: Cloud WAN **Routing Policy** rules (route filters on attachments and shares) (requirements §13, item 8). A route that a routing policy would legitimately admit across an unshared pair is impossible by construction, because routing policies filter routes but don't create sharing. So this gap can only hide a leak that a routing policy should have dropped, never create a false leak.

**TGW.** For each route table, for each route from `SearchTransitGatewayRoutes`. **Verified (task 0.4)** against the botocore 1.43.111 `ec2` model: `Filters` is **required** (valid names: `attachment.transit-gateway-attachment-id`, `attachment.resource-id`, `attachment.resource-type`, `prefix-list-id`, `route-search.{exact,longest-prefix,subnet-of,supernet-of}-match`, `state` ∈ active|blackhole, `type` ∈ propagated|static). `MaxResults` ranges 5–1000 (default 1000). The response now carries `NextToken` and `AdditionalRoutesAvailable`, and botocore ships a paginator. Collector strategy: one paginated call per table with `Filters=[{Name: state, Values: [active, blackhole]}]`. That covers checks 2, 3 and 5 in one pass; check 2 filters to active in code. Fallback: if a page returns `AdditionalRoutesAvailable=true` with no `NextToken` (the older capped behavior), the collector re-queries split by `type` and then by `route-search.subnet-of-match` on the RFC 1918 /8, /12 and /16 supernets plus `0.0.0.0/0` exact. If that still doesn't complete, it sets `routes_truncated=true`, and the report surfaces it as a `system` finding so the table is never treated as fully evaluated: resolve the route's attachment → its `Environment` tag (or its ID). Look up the isolation matrix (§7.2): the table's key (tag value, then ID) must list the source's tag value or ID. Not listed → `tgw-prefix-leak`. Blackhole routes are excluded here (check 3 owns them).

**Finding identity for both variants:** one finding per `(destination route table, prefix, source attachment)`, never one finding per leak set. A table that sees 40 leaked prefixes from one attachment yields 40 findings with 40 stable IDs, so fixing 39 of them resolves 39 findings and leaves one KNOWN, rather than producing a "changed" blob. Grouping those 40 into one incident is the investigation's job (§11.3), not the check's.

### 4.3 Check 3 — blackhole

Any route with `State == "BLACKHOLE"` (Cloud WAN) or `State == "blackhole"` (TGW) → `blackhole-route` with table, prefix, type (static/propagated). Always drift.

**TGW isolation as built (tasks.md 2.2, `checks/check2_tgw.py`):**

- **Which tables are checked:** only tables the matrix names. A table is matched by its tag value first, then by its route-table ID. The matrix is an opt-in list, not a default deny for the whole account.
- **Source domain:** the next-hop attachment's tag. If the attachment is untagged, its associated route table (tag value and ID) is used instead. If neither exists, the route is skipped; check 1 already reports the missing tags.
- **Isolation names:** checked against the collected route tables in `evaluate`. A name that matches nothing turns the file into `intent-file-rejected` with its line number. That check is skipped while any Region is not evaluated, because the missing tables could be in that Region.

### 4.4 Check 4 — DX redundancy

For each pair in `dx_redundancy_pairs`: look up both VIF IDs across all Regional `DescribeVirtualInterfaces` snapshots. Rules: member not found → `redundancy-member-missing`; `virtualInterfaceState != available` → `redundancy-member-down`; any `bgpPeers[].bgpStatus != up` → `redundancy-bgp-down` (one per peer); both members down → `redundancy-pair-down` (and the two member findings). A pair that is fully healthy produces nothing.

**As built (tasks.md 2.3, `checks/check4_redundancy.py`):**

- **BGP findings on a down VIF:** `redundancy-bgp-down` is not emitted for a VIF that is already down. Its peers are down as a consequence, and `member-down` already says so.
- **Not found while collection was incomplete:** if a member isn't found and any Region was not evaluated, the result is `redundancy-member-unverified` (`system`), never drift. `pair-down` is withheld in that case.
- **Region discovery:** a VIF can live in a Region with no transit gateway. `init` therefore probes `DescribeVirtualInterfaces` in every enabled Region for the VIF IDs the intent file names, and adds the owning Regions to the scope. A Region that can't be probed is included (fail-closed). This adds `directconnect:DescribeVirtualInterfaces` to the `init` role.

### 4.5 Check 5 — limits

A limit registry (`limits.py`) with one entry per row of §5.1: `name`, `scope` (VIF / DXGW-TGW association / DXGW-core network attachment / TGW / core network), `limit_source` (`configured` | `static`), `default_limit`, `doc_url`. For each resource in scope compute `count`, resolve `limit`, compute `pct`; `pct >= threshold` → `limit-threshold` with `name`, `count`, `limit`, `pct`, `doc_url`.

| Limit | Count from | Limit from |
|---|---|---|
| On-prem→AWS routes per BGP session per address family | Received-route count is not exposed by API; the check counts **the VIF's advertised-from-on-prem routes as installed** in the attached TGW route table (`SearchTransitGatewayRoutes`, filter `type=propagated`, attachment = the DX gateway attachment) or Cloud WAN segment routes whose destination attachment is the DX attachment, split by address family. **The finding text must contain the word "approximate"** and state why: installed routes undercount received routes when inbound filtering, route aggregation, or multiple VIFs feeding one attachment are present. Fixed template: `Approximate: N installed routes of M allocated (P %) on <vif> <family>; received count may be higher than installed.` | The VIF's configured prefix allocation. **Verified (task 0.2):** `DescribeVirtualInterfaces` returns `prefixPoolAllocatedCountIpv4` and `prefixPoolAllocatedCountIpv6` (integers) on each `VirtualInterface`. botocore 1.43.111 documents them as "the number of inbound IPv4/IPv6 route prefixes allocated to the virtual interface" and says they don't apply to public VIFs. The check reads the field for the family being counted. If the field is absent (an older VIF, or a response without it), the limit falls back to the documented default of 100 and the finding is labeled `assumed-default`. Public VIFs are out of scope. |
| TGW→on-prem prefixes per transit VIF | `len(allowedPrefixesToDirectConnectGateway)` on `DescribeDirectConnectGatewayAssociations` | Static 200 |
| Core network→on-prem via DXGW attachment | Installed routes in the segment/edge of the DX gateway attachment (upper bound; labeled as such) | Static 5,000 |
| Total routes per TGW | Sum of `SearchTransitGatewayRoutes` counts across the TGW's tables | Static 10,000 |
| Routes per core network | Sum of `GetNetworkRoutes` counts across all segment × edge tables | Static 10,000 |

Because the finding ID excludes the count (this doc §5), a threshold crossing stays KNOWN while the count climbs; the report shows the current count.

### 4.6 Check 6 — hybrid path intent

For each `hybrid_paths[]` entry: find the installed route(s) for `prefix` (exact match; longest-prefix mismatch is reported as `hybrid-path-prefix-not-found`). `exit_region` set and the route's installed next-hop attachment is in another edge/Region → `hybrid-path-wrong-exit-region`. `preferred` set and the installed path's attachment ≠ preferred → `hybrid-path-not-preferred`. `backup` set and no route for the prefix via the backup attachment → `hybrid-path-backup-absent`.

**Verified (task 0.3)** against the botocore 1.43.111 `networkmanager` model: `GetNetworkRoutes` (requires `GlobalNetworkId` and `RouteTableIdentifier`) returns **installed routes only**. `State` ∈ `ACTIVE`|`BLACKHOLE`, `Type` ∈ `PROPAGATED`|`STATIC`, with `Destinations[]` carrying the attachment, segment and edge. There is no field or filter for received-but-not-preferred routes. So the backup rule differs by platform:

- **TGW:** `SearchTransitGatewayRoutes` returns every attachment for an ECMP or equal route in `TransitGatewayAttachments[]`. The backup rule passes if the backup attachment appears for the prefix in any evaluated table. Otherwise the attachment-level fallback below applies.
- **Cloud WAN, and TGW when the backup isn't in the installed set (the normal state for an active/passive backup):** attachment-level check only. The backup attachment must exist and be `AVAILABLE`. For a DX backup, its VIF must be `available` with all BGP peers `up`. For a VPN backup, at least one tunnel must be `UP`. If those hold, the result is the informational finding `hybrid-path-backup-unverifiable` (stating "backup attachment healthy; whether it advertises <prefix> cannot be verified from the control-plane APIs"), not drift. Only an absent or unhealthy backup attachment is `hybrid-path-backup-absent` drift. The README states this limit.

**As built (tasks.md 2.4, `checks/check6_hybrid_path.py`):**

- **Prefix match:** exact, after normalization.
- **Exit Region:** a Cloud WAN route's exit is its destination edge. A TGW route's exit is the table's Region, except a peering next hop, which isn't judged.
- **`preferred`:** judged only in that resource's Region; everywhere for a DX gateway. A preferred VIF matches the DX gateway it is attached to.
- **`backup` health:** VPN tunnel status comes from the new `ec2:DescribeVpnConnections` call in `collect-region`. TGW attachment, Cloud WAN attachment and DX gateway association health come from data already collected.
- **"Not found" while collection was incomplete:** becomes `hybrid-path-unverified` (`system`), never drift.

## 5. Finding model and deterministic ID

```python
@dataclass(frozen=True)
class Finding:
    check: str          # "check1" … "check6" | "informational" | "system"
    kind: str           # e.g. "tgw-prefix-leak", "untagged-attachment", "intent-file-rejected", "region-not-evaluated"
    severity: str       # "drift" | "informational" | "system"
    region: str         # or "global" for Cloud WAN policy-level findings
    identity: tuple[str, ...]   # the resource identifiers that define *this* drift, sorted, lowercase
    expected: dict
    observed: dict
    context: dict       # segment / route table, Environment tag, affected prefixes, limit doc_url
```

**ID:** `finding_id = "f-" + sha256(f"{kind}|{region}|" + "|".join(identity)).hexdigest()[:20]`

- `identity` contains only stable identifiers: attachment ID, route-table ID or `(core_network_id, segment, edge)`, prefix in canonical form, VIF ID, limit name. It **never** contains counts, timestamps, tag values that are the observed side of the comparison, or ordering-dependent lists (lists are sorted before joining).
- A separate `payload_hash = sha256(canonical_json(expected, observed))` is stored for change detection; a KNOWN finding whose payload changed is still KNOWN, with `changed: true` in the report.
- Unit tests prove: field-order independence, timestamp independence, sort independence, and that two different drifts never collide on the fixture suite.

### 5.1 Drift-state table (DynamoDB)

| PK | Attributes | Purpose |
|---|---|---|
| `F#<finding_id>` | `check, kind, region, first_seen, last_seen, status (open \| resolved), resolved_at, payload_hash, last_payload (S3 pointer)` | Finding history |
| `META#marker` | `last_successful_full_run, run_id` | Lookback origin (§9.2) |
| `TOKEN#<incidentId>` | `task_token, run_id, ttl` | Callback correlation (this doc §3.3) |
| `RUN#<run_id>` | `started, finished, scope, regions_evaluated, regions_not_evaluated, counts, ttl=90d` | Operational history |

Diff algorithm: load all `F#` items with `status=open` (Query on a GSI `status-index`), compare by `finding_id` with this run's findings. Present + not open → NEW (put, `first_seen=now`). Present + open → KNOWN (update `last_seen`). Open + absent this run → RESOLVED (update `status=resolved`, TTL 90 days), **but only if the finding's source was evaluated this run**; otherwise it is carried as KNOWN with `unverified: true`.

As built (tasks.md 1.23, `drift_core/diff.py`):

- **Source** is stored on every `F#` item. Cloud WAN findings (`core_network_id` in context) have source `cloudwan`, not their edge Region, because Cloud WAN is collected once globally and can fail independently of every Regional collection. TGW and DX findings use their Region; run-level findings use `global`.
- **`now` is the run's `started_at`**, not wall-clock time. Ages are therefore whole days between scheduled runs, and a re-driven execution writes the same timestamps.
- A RESOLVED finding that reappears later is NEW again with a fresh `first_seen`.
- `system` findings (not evaluated, truncated, intent rejected or unreadable) go through the same diff, so a Region failing three days running reads as KNOWN for 3 days.

## 6. DevOps Agent hand-off

### 6.1 Webhook request

Per the [webhook documentation](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-integrations-and-knowledge-invoking-devops-agent-through-webhook.html): POST JSON with headers `Content-Type: application/json`, `x-amzn-event-timestamp: <ISO-8601 .000Z>`, `x-amzn-event-signature: base64(HMAC-SHA256(secret, f"{timestamp}:{body}"))`.

```json
{
  "eventType": "incident",
  "incidentId": "nrdc-<run_id>-<batch_n>",
  "action": "created",
  "priority": "HIGH" | "MEDIUM",
  "title": "Network routing drift: <N> new findings (<kinds summary>)",
  "description": "<structured text block, see 6.2>",
  "timestamp": "<ISO-8601>",
  "service": "network-routing-drift-checker",
  "data": {"run_id": "...", "batch": 1, "batches": 1}
}
```

- `priority` is `HIGH` if any NEW finding is a blackhole, a redundancy or BGP-down finding, or a `limit-threshold` on the on-prem→AWS allocation; otherwise `MEDIUM`.
- **Only `title`, `description`, `priority` reach the agent** (webhook contract). `data` is for our own correlation only.
- `description` is capped at a configurable size (default 12 KB, well under typical webhook limits). NEW findings are batched so each investigation receives at most `max_findings_per_investigation` (default 25), grouped so that findings sharing a resource (same VIF, same route table) land in the same batch. Multiple batches mean multiple investigations and multiple task tokens; the state machine waits for all (Map over batches with `waitForTaskToken` inside) and the report links each.
- `incidentId` is unique per run and batch; DevOps Agent deduplicates on it.

### 6.2 Description block (what the agent sees)

```
[INVESTIGATION_ID:nrdc-2026-10-13T05:00:00Z-a1b2c3-1]
NETWORK ROUTING DRIFT — NEW FINDINGS (run 2026-10-13T05:00Z, lookback from 2026-05-11T05:00Z)
Account 123456789012. Skill to apply: network-routing-drift (with aws-routing).
Return the structured result block defined by the skill.

[1] id=f-9c1e… kind=redundancy-bgp-down region=eu-central-1
    resource=dxvif-0123abcd pair=frankfurt-site-a peer=169.254.x.x/ipv4
    expected: bgpStatus=up  observed: bgpStatus=down since (unknown)
    context: Environment=prod carries prefixes 10.100.0.0/16, 10.101.0.0/16 (+10 more)
[2] id=f-77ab… kind=blackhole-route region=eu-central-1
    table=tgw-rtb-0aaa (Environment=prod) prefix=10.100.5.0/24 type=static
…
Lookback window for change events: 2026-05-11T05:00Z → 2026-10-13T05:00Z.
```

### 6.3 Callback result schema (what the agent returns)

The skill instructs the agent to end its investigation with a fenced block the `callback` function parses:

```json
{
  "schema": "nrdc-investigation/v1",
  "incidentId": "nrdc-<run_id>-<batch_n>",
  "investigation_url": "https://…",
  "incidents": [
    {
      "rank": 1,
      "title": "Frankfurt site-A Direct Connect VIF BGP down",
      "member_finding_ids": ["f-9c1e…", "f-77ab…", "…"],
      "root_cause_hypothesis": "…",
      "confidence": "high" | "medium" | "low",
      "evidence": [
        {"type": "cloudtrail", "event_id": "…", "event_name": "…", "time": "…", "actor": "… | unknown"},
        {"type": "health", "event_arn": "…"},
        {"type": "state", "resource": "dxvif-…", "observation": "bgpStatus=down"}
      ],
      "actor_identified": true | false,
      "blast_radius": {"prefixes": 12, "attachments": 1, "domains": 1, "environment": "prod", "score": 1210},
      "stable_for": "P0D" | "P14D",
      "validation_commands": ["aws directconnect describe-virtual-interfaces --virtual-interface-id …"]
    }
  ],
  "unassigned_finding_ids": [],
  "notes": "…"
}
```

Validation in `callback` is **scoped to the batch**, because `incidentId` is per batch and each callback sees only its batch's findings: `schema` matches; `incidentId` resolves to a `TOKEN#` item; **every finding ID in this batch appears exactly once across `member_finding_ids ∪ unassigned_finding_ids`, and no ID outside this batch appears**; `confidence` ∈ the fixed scale; every entry of `validation_commands` matches `^aws [a-z0-9-]+ (describe|get|list|search)-[a-z0-9-]+` and contains no `;`, `&&`, `|`; `rank` is a permutation of 1..n within the batch. Failure → `SendTaskFailure(SCHEMA_INVALID)` for **that batch only** → that batch takes the raw-findings path (this doc §3.2); other batches are unaffected. `MergeInvestigations` then asserts the run-level invariant: the union of all successful batches' `member_finding_ids ∪ unassigned_finding_ids` plus all failed batches' finding sets equals the run's NEW set exactly. A violation there is a bug in batching, not in the agent, and is logged as `system` and surfaced in the report. Ranking in `MergeInvestigations` is recomputed across all successful batches so the report shows one ordered list, not one per batch.

**Blast-radius score (defined, computed by the skill from counts it reports):** `score = (prefixes + 10·attachments + 100·domains) × env_weight`, `env_weight` = 10 for a production-tagged domain, 3 for staging/shared, 1 otherwise, tag values matched case-insensitively against a configurable list. Ties broken by `confidence` (high first), then by `kind` order (blackhole, redundancy, leak, wrong-domain, limit, hybrid-path). The `callback` function **recomputes** the score from the reported counts and re-sorts; the agent's `rank` is advisory, the code's order is what the report shows. (This is the precision-tool rule applied to ranking: the LLM gathers the counts, code does the arithmetic.)

### 6.4 Skill package

```
devops-agent-skill/network-routing-drift/
├── SKILL.md            # frontmatter: name, description (activation phrases incl. "NETWORK ROUTING DRIFT — NEW FINDINGS"), version
│                       # body: §11.3 methodology per finding kind, grouping rules, blast-radius definition,
│                       #       confidence scale, evidence citation rule, "no evidence found" rule, unknown-actor rule,
│                       #       hard boundaries §11.4, output block (6.3) verbatim template
├── references/
│   ├── finding-kinds.md            # every kind with its fields and what to investigate
│   ├── cloudtrail-event-map.md     # kind → CloudTrail eventNames to search (e.g. CreateTransitGatewayRoute,
│   │                               #   ReplaceTransitGatewayRouteTableAssociation, PutCoreNetworkPolicy,
│   │                               #   ExecuteCoreNetworkChangeSet, DeleteVirtualInterface)
│   ├── health-event-map.md         # kind → Health service/eventTypeCode families (AWS_DIRECTCONNECT_*, AWS_EC2_* TGW)
│   └── output-schema.json          # 6.3 as JSON Schema
├── evals/                          # trigger + functional evals in the tools-for-devops-agent format
├── README.md, CHANGELOG.md
└── network-routing-drift.zip       # packaged for upload
```

The skill depends on the public `aws-routing` skill for route-evaluation reasoning and says so; the README tells the customer to upload both.

**As built (tasks.md 3.7, 2026-10-15):**

- **The zip isn't committed.** `scripts/package-skill.sh` builds `dist/network-routing-drift.zip` (git-ignored) and fails if the schema copy differs from `src/drift_core/investigation_schema.json`. `evals/` stays out of the upload.
- **`tests/unit/test_skill_package.py`** checks:
  - the frontmatter rules from the [DevOps Agent Skills docs](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-devops-agent-skills.html) (name format, description of 100–1024 characters);
  - that the schema copy is byte-identical;
  - that the SKILL.md output template and every example command pass the callback's own `validate_result`;
  - that commands the skill forbids are rejected;
  - that `references/finding-kinds.md` names every drift kind the checks emit.
- **Two changes learned from the first live run:**
  - Without the skill, the agent produced a good investigation but had no output format.
  - The agent kept posting messages after its conclusion. So `callback` now takes the newest assistant message that *contains* an `nrdc-investigation/v1` block, not simply the newest one.
  - The run's mitigation step proposed `replace-transit-gateway-route`. That stayed in DevOps Agent and never reached the report, but the skill now explicitly says that for `nrdc-` incidents a mitigation is a prose recommendation only.

## 7. IAM

### 7.1 Per-check read actions against customer resources (the lint allowlist)

| Check / step | Service | Actions | Resource |
|---|---|---|---|
| Init: Regions | EC2 | `ec2:DescribeRegions` | `*` (API requires it; read-only) |
| Init + Collect: Cloud WAN | Network Manager | `networkmanager:ListCoreNetworks`, `networkmanager:GetCoreNetwork`, `networkmanager:GetCoreNetworkPolicy`, `networkmanager:ListAttachments`, `networkmanager:GetNetworkRoutes`, `networkmanager:ListTagsForResource` | `arn:aws:networkmanager::<acct>:core-network/*`, `…:attachment/*`, `…:global-network/*`. **Verified against the [Network Manager authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_networkmanager.html): `GetNetworkRoutes` is scoped to resource type `global-network*`**, so the policy must name the global network ARN, not the core network. `ListCoreNetworks` has no resource type (`*`). |
| Check 1, 2, 3, 5 (TGW) | EC2 | `ec2:DescribeTransitGateways`, `ec2:DescribeTransitGatewayRouteTables`, `ec2:DescribeTransitGatewayAttachments` | `*` (these do not support resource-level restriction per the [EC2 authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html)) |
| Check 1, 2, 3, 5 (TGW routes) | EC2 | `ec2:SearchTransitGatewayRoutes` | `arn:aws:ec2:<region>:<acct>:transit-gateway-route-table/*`. **Fixed 2026-10-18 (pre-release review finding):** this action DOES support resource-level permissions, unlike the other TGW `Describe*` actions above — the original `Resource: "*"` on the shared statement was wrong, not a documented limitation. Split into its own statement so the other, genuinely unscopable `Describe*` actions keep `*`. |
| Check 4, 5, 6 (DX) | Direct Connect | `directconnect:DescribeDirectConnectGateways`, `directconnect:DescribeDirectConnectGatewayAssociations` | `arn:aws:directconnect::<acct>:dx-gateway/*` (global, no Region in the ARN). **Fixed 2026-10-18 (pre-release review finding):** these DO support resource-level permissions on `dx-gateway` per the [Direct Connect authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_directconnect.html) — the original `Resource: "*"` with the comment "Describe APIs are account-scoped" was factually wrong. |
| Check 4, 5, 6 (DX VIFs) | Direct Connect | `directconnect:DescribeVirtualInterfaces` | `arn:aws:directconnect:<region or *>:<acct>:dxvif/*`, `…:dxcon/*`, `…:dxlag/*` (Regional; `init`'s discovery call uses Region `*` since VIF Regions aren't known yet, `collect-region`'s call is scoped to its own Region). Same fix as above: `DescribeVirtualInterfaces` supports resource-level permissions on these three types. |
| Hybrid path backup via VPN (check 6) | EC2 | `ec2:DescribeVpnConnections` | `*` |

**Not granted, deliberately:** `networkmanager:StartRouteAnalysis` (creates an analysis object; left to DevOps Agent's own role if the customer wants it), anything under `cloudtrail:*`, `health:*` (the investigation is DevOps Agent's job under its own role), any `servicequotas:*` (limits are static or read from the resource).

**Customer prerequisite that follows from this (see §15 of `requirements.md`, task 3.8):** because the checker grants none of the investigation reads, the **Agent Space's role in the networking account** (primary source when it's the same account, secondary source when it isn't, this doc §3.3a) must hold CloudTrail, AWS Health, Network Manager, EC2 Transit Gateway and Direct Connect read access. Without them every investigation returns "no evidence found" at `low` confidence and the checker looks broken when it is not. The README states this next to the hand-off setup, and the solution ships a CloudFormation snippet for the Agent Space role.

### 7.2 Writes to the solution's own resources (ARN-scoped, tag-conditioned where the service supports it)

| Function | Actions | Resource |
|---|---|---|
| all | `logs:CreateLogStream`, `logs:PutLogEvents` | its own log group ARN |
| all | `xray:PutTraceSegments`, `xray:PutTelemetryRecords` | `*` (service requirement) |
| init | `s3:GetObject`, `s3:GetObjectVersion` | `<bucket>/intent/routing-intent.yaml` |
| init, collect-*, evaluate, diff, report, callback | `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` (prefix condition `runs/*`) | `<bucket>/runs/*`, `<bucket>` |
| diff, investigate, callback, marker | `dynamodb:GetItem`, `PutItem`, `UpdateItem`, `Query` | drift-state table ARN + `status-index` ARN, `Condition: aws:ResourceTag/agent-managed = "true"` |
| investigate | `ssm:GetParameter` (`WithDecryption`) | the one SecureString parameter ARN |
| investigate | `kms:Decrypt` | the SSM parameter's key (if customer-managed) |
| callback | `states:SendTaskSuccess`, `states:SendTaskFailure`, `states:SendTaskHeartbeat` | **Resolved 2026-10-15: scoped to the state machine ARN (`grantTaskResponse`), verified live with a real `SendTaskSuccess` and `SendTaskHeartbeat` (§14 item 5).** Original note: The [Step Functions authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_stepfunctions.html) lists no resource type for these three actions, which implies `*`. The reference implementation uses CDK `stateMachine.grantTaskResponse(callback)`, which scopes them to the state machine ARN, and that implementation works. **Rule:** start with the scoped grant (`grantTaskResponse`). Task 3.3's integration test sends a real `SendTaskSuccess` under the scoped policy. If it succeeds, keep the scoped grant and update this cell. If it returns `AccessDenied`, switch to `*` and keep this residual-risk statement: the `callback` role could complete a task token belonging to any state machine in the account if it possessed that token. Mitigations: tokens are never logged, the role is attached only to `callback`, `callback` only uses tokens it reads from its own `TOKEN#` items, and a token is unguessable and single-use. Documented in the README security section either way. |
| callback | `aidevops:ListJournalRecords` | **Same-account:** `arn:aws:aidevops:<region>:<acct>:agentspace/<DevOpsAgentSpaceId>` (verified, task 0.1; the reference uses `agentspace/*`, scoped tighter here). **Cross-account:** not on the callback role. |
| callback (cross-account only) | `sts:AssumeRole` | `arn:aws:iam::<DevOpsAgentAccountId>:role/nrdc-journal-reader-<N>-<region>` (this doc §3.3a) |
| companion stack: journal reader (account D) | `aidevops:ListJournalRecords` | the one Agent Space ARN in D; trust pinned to the callback role ARN |
| companion stack: event forwarder (account D) | `lambda:InvokeFunction` | the one `callback` function ARN in N; trust `events.amazonaws.com`, `aws:SourceArn` = the companion rule |
| callback (async-invoke failure destination) | `sqs:SendMessage` | the callback DLQ ARN |
| EventBridge rule → callback | `lambda:InvokeFunction` resource policy. Same-account: `SourceArn` = the rule ARN. Cross-account: principal = the event-forwarder role in D | the `callback` function |
| state machine role | `lambda:InvokeFunction` per function ARN; `sns:Publish` topic ARN; `dynamodb:UpdateItem` table ARN | scoped |
| scheduler role | `states:StartExecution` | state machine ARN |

### 7.2a As granted in Phase 1 (tasks.md 1.8)

The Phase 1 roles grant a **subset** of §7.1. Each function gets only what its code calls:

| Function | Customer reads | Own resources |
|---|---|---|
| `init` | `ec2:DescribeRegions`, `ec2:DescribeTransitGateways` (`*`); `networkmanager:ListCoreNetworks` (`*`), `GetCoreNetwork` (`core-network/*`); `directconnect:DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations` (`*`) | `s3:GetObject`/`GetObjectVersion` on the intent key; `s3:ListBucket` on the bucket (so an absent intent file reads as "absent," not AccessDenied); `s3:GetObject`/`PutObject` on `runs/*`; `dynamodb:GetItem` (marker); KMS |
| `collect-cloudwan` | `networkmanager:ListCoreNetworks` (`*`), `GetCoreNetwork`, `GetCoreNetworkPolicy` (`core-network/*`), `ListAttachments` (`attachment/*`, verified resource type), `GetNetworkRoutes` (`global-network/*`) | `runs/*`; KMS |
| `collect-region` | `ec2:DescribeTransitGateways`, `DescribeTransitGatewayRouteTables`, `DescribeTransitGatewayAttachments`, `SearchTransitGatewayRoutes`; `directconnect:DescribeVirtualInterfaces` (all `*`) | `runs/*`; KMS |
| `evaluate`, `report` | none | `runs/*`; KMS |
| `diff` | none | `runs/*`; `dynamodb:Query` on `status-index`; `dynamodb:BatchWriteItem`/`PutItem` on the table **with** `aws:ResourceTag/agent-managed = true`; KMS |
| state machine | none | `lambda:InvokeFunction` on the six functions; `sns:Publish` on the topic; `dynamodb:UpdateItem` on the table (marker); KMS |
| scheduler | none | `states:StartExecution` on the state machine; trust is limited by `aws:SourceAccount` |

Roles have **no** managed policies. Logs permissions are scoped to each function's own log group. **Verified at first deploy (2026-10-13, lab account, us-east-1):** the `aws:ResourceTag/agent-managed` condition on the DynamoDB writes is evaluated and passes. The `diff` function wrote 7 `F#` items and 2 `RUN#` items under the scoped policy.

### 7.3 Deny-by-default IAM lint (`tests/iam/`)

Synthesizes the CDK template, extracts every policy statement, and fails if any statement: contains an action not in the union of §7.1 and §7.2; contains `*` or a trailing wildcard in an action; grants a write action (anything not matching `^(ec2|networkmanager|directconnect|aidevops):(Describe|Get|List|Search)`) with `Resource: "*"` except the explicitly listed service-requirement cases (`xray:Put*`; `states:SendTask*` only if task 3.3 recorded that the scoped grant is denied); or names any action from the `iam-permission-boundary` BLOCKED list. The allowlist is a checked-in file generated from §7.1/§7.2, so changing the policy means changing the spec.

## 8. Configuration (stack parameters → env vars via `config.py`)

| Parameter | Default | Notes |
|---|---|---|
| `ScheduleExpression` | `cron(0 5 * * ? *)` | EventBridge Scheduler syntax |
| `ScheduleTimezone` | **no default** — required; the stack fails validation (CloudFormation parameter with `AllowedPattern` for an IANA name and no `Default`, plus a CDK synth-time check) until the customer supplies one. README lists common IANA names. | DST-safe; never guessed |
| `RegionAllowlist` / `RegionExcludeList` | empty | Comma-separated; intent file §7.2 `regions` block overrides if present |
| `RegionConcurrency` | `4` | Map `MaxConcurrency` |
| `EnvironmentTagKey` | `Environment` | §6 |
| `ProductionTagValues` | `prod,production` | For blast-radius weight |
| `LimitThresholdPercent` | `80` | Applies to all five limits; per-limit override `LimitThresholdOverrides` JSON |
| `IntentObjectKey` | `intent/routing-intent.yaml` | |
| `EnableDevOpsAgentHandoff` | `false` | |
| `DevOpsAgentWebhookUrl` | empty | Required iff handoff enabled. Must match `https://event-ai.<region>.api.aws/webhook/generic/<id>`, and `<region>` must equal the stack Region (this doc §3.3) |
| `WebhookSecretParameterName` | empty | SSM SecureString **name**; the value is never a parameter |
| `DevOpsAgentSpaceId` | empty | Required iff handoff enabled (verified need, task 0.1). Scopes `aidevops:ListJournalRecords` and the EventBridge rule filter `detail.metadata.agent_space_id`. A CloudFormation rule enforces all-three-or-none across URL, secret name and space ID; a half-configured state fails the deploy |
| `DevOpsAgentAccountId` | the stack's account | 12 digits. Equal to the stack account → same-account (§3.3). Different → cross-account (§3.3a): the callback assumes the journal reader, and `deploy.sh` needs `DEVOPS_AGENT_PROFILE` to deploy the companion stack. Ignored when the hand-off is disabled |
| `InvestigationTimeoutSeconds` / `InvestigationHeartbeatSeconds` | `2700` / `2700` (was 900; raised after the live run, §3.3) | Heartbeat stays equal to the timeout because the progress events are one-shot (this doc §3.4) |
| `InvestigationConcurrency` | `2` | Map `MaxConcurrency` over batches; keeps parallel investigations within Agent Space limits |
| `MaxFindingsPerInvestigation` | `25` | |
| `LogRetentionDays` | `90` | Allowed values are the CloudWatch Logs retention steps of 90 days or more |
| ~~`SnapshotRetentionDays`~~ | fixed 30 | As built: a fixed S3 lifecycle on `runs/`. A CloudFormation parameter can't feed the CDK lifecycle rule. Edit `infra/lib/drift-checker-stack.ts` to change it |

**As built (tasks.md 1.4).** All of the above are CloudFormation parameters, so validation happens when CloudFormation creates or updates the stack, not at `cdk synth`:

- `ScheduleTimezone` has no default and an IANA `AllowedPattern`, so CloudFormation refuses to create the stack without it.
- The hand-off settings are enforced by two `Rules` (all three set when enabled, all three empty when disabled) and an `AllowedPattern` on the webhook URL.
- **Webhook Region = stack Region** can't be a CloudFormation rule (no substring matching). As built (Phase 3): a runtime check in `investigate` (fail closed, before the secret is read) plus a pre-deploy check in `scripts/deploy.sh`, which also checks that the secret parameter is a SecureString.
| `NotificationEmail` | optional | Subscribes to the topic on deploy |

## 9. Observability and alarms

- Structured JSON logs (`run_id`, `region`, `check`, `duration_ms`, counts). The HMAC secret and the webhook URL are on a redaction list in the logger; a unit test asserts neither appears in any log line or in the state machine input/output. The Lambda returns only IDs and a status, and with `waitForTaskToken` the task output is the callback's SendTaskSuccess payload (IDs, counts, artifact key, link), which never contains either value.
- X-Ray on all functions and the state machine.
- Custom metrics: `FindingsNew`, `FindingsKnown`, `FindingsResolved`, `RegionsNotEvaluated`, `InvestigationFailed`, `RunDurationSeconds`.
- Alarms (all → the SNS topic): `ExecutionsFailed ≥ 1` (1 period); **missed run**: `ExecutionsStarted < 1` over a period of schedule interval + 1 h; `RegionsNotEvaluated ≥ 1` for 3 consecutive runs; **`InvestigationFailed ≥ 1`** (1 period; a timed-out or failed batch, this doc §3.2/§3.4); **`CallbackDlqMessages ≥ 1`** (an EventBridge-delivered completion event the `callback` could not process after async retries, this doc §3.3); Lambda error rate > 5 %. **As built in Phase 1** (9 alarms):

- `ExecutionFailed` (failed + timed out + aborted ≥ 1 per hour).
- `MissedRun`: no execution started in 26 consecutive hours, using 1-hour periods with missing data treated as breaching and a **wall clock evaluation window** (UTC). A daily period would false-alarm every morning before the run. This assumes a daily schedule. The wall clock window is required: with the default sliding window, CloudWatch reused the last real datapoint and the alarm never fired (found live 2026-10-14).
- **Topic policy:** the report topic's policy must explicitly allow `cloudwatch.amazonaws.com` to `sns:Publish`, scoped to this account's alarms. The stack's TLS-only policy replaces the SNS default policy, and without the Allow every alarm action fails silently (found live 2026-10-14). The KMS key policy already grants CloudWatch `GenerateDataKey*` and `Decrypt`.
- `RegionsNotEvaluated` ≥ 1 on 3 consecutive daily datapoints.
- Six per-function `LambdaErrorRate` alarms. Alarm math expressions are capped at 10 metrics, so one aggregate alarm over six functions isn't possible.

Phase 3 adds `InvestigationFailed` (Sum ≥ 1 per hour, from MergeInvestigations' EMF line) and `CallbackDlqMessages` (DLQ visible messages ≥ 1), so 11 alarms. **As built:** the four hand-off functions get no error-rate alarm of their own. Their failures already surface as `InvestigationFailed`, `ExecutionFailed` or `CallbackDlqMessages`. The callback DLQ is wired by hand (`CfnEventInvokeConfig`, 2 retries, 1 h max age), because CDK's SQS destination grants `kms:ReEncrypt*`, which the IAM lint rejects. The state machine timeout went from 30 minutes to 2 hours, so investigation batches fit; each batch keeps its own timeout. The drift report also carries the per-batch failure line, so the alarm is the operational signal and the report is the human-readable one.

## 10. Tool classification (per `ai-agent-standards`)

The only LLM in this solution is AWS DevOps Agent, instructed by the skill. Everything the solution itself runs is pure code. The classification below is still mandatory so a reader knows which code fetches and which code decides.

| Component | Classification | Input → Output | LLM inside? |
|---|---|---|---|
| `collect-cloudwan`, `collect-region` | Data retrieval | Region (or the global Network Manager endpoint) → snapshot JSON (raw API responses, normalized) | No |
| `init` (intent validator part) | Precision | YAML → validated intent model or rejection with line/reason | No |
| `init` (Region discovery part) | Data retrieval | API → Region list | No |
| `evaluate` (six checks) | Precision | snapshots + intent → findings[] | No |
| `finding.py` (ID derivation) | Precision | identity tuple → stable ID | No |
| `diff` | Precision | findings + state → NEW/KNOWN/RESOLVED | No |
| `limits.py` (count, pct) | Precision | counts + limits → threshold findings | No |
| `webhook.py` (batching, HMAC) | Precision | NEW findings → signed request(s) | No |
| `callback` (schema validation, blast-radius recompute, re-sort) | Precision | agent result → validated, re-ranked incidents | No |
| `report` | Precision | run artifacts → message text | No |
| **AWS DevOps Agent + `network-routing-drift` skill** | Reasoning (external) | findings → root-cause hypotheses, evidence, grouping, counts | Yes — the only one |

Rule applied: the LLM never does arithmetic that the report depends on. It reports counts it observed; `callback` computes scores and order.

## 11. Security summary (per `security-policies`, `iam-permission-boundary`)

- Read-only against customer resources; writes ARN-scoped to agent-managed resources; no `MUTATING_ACTIONS.md` because there are no mutating tools (§12).
- Secrets: SSM SecureString only; read at runtime; redacted in logs; never in Step Functions state.
- **Ingress surface: none (verified, task 0.1).** Every function is invoked by Step Functions, EventBridge Scheduler, or an EventBridge rule on the default bus (`source: aws.aidevops`, filtered to `DevOpsAgentSpaceId`). There is no VPC, function URL, API Gateway or load balancer. The IAM lint and a synth test assert that no `AWS::Lambda::Url`, `AWS::ApiGateway*`, `AWS::ApiGatewayV2*` or `AWS::ElasticLoadBalancingV2*` resource exists in the template. Event authenticity: only AWS services can emit `aws.*` sources to the bus. In the cross-account shape (this doc §3.3a), `callback` has one more invoker: account D, named in the resource policy. Inside D, only the companion stack's event-forwarder role is granted `lambda:InvokeFunction` on it, so another principal in D would also need an IAM grant from D's administrators. No other account can invoke it. `callback` additionally drops any event whose first journal message lacks an `nrdc-` `[INVESTIGATION_ID:…]` tag that matches a live `TOKEN#` item.
- **Outbound:** HTTPS to AWS endpoints and the one webhook URL. `webhook.py` rejects any URL that isn't `https://event-ai.<region>.api.aws/…` (Bandit B310 posture).
- **Agent output reaching the report** (added 2026-10-16, tasks.md 4.4): the result is schema-validated per batch, scores and order are recomputed by code, validation commands are read-only by regex, and `investigation_url` is kept only if it points into the same Agent Space web app as the default link (`https://<agent_space_id>.aidevops.global.app.aws/`); otherwise the default link is used. Full threat model: `docs/security/threat-model.md`.
- **`states:SendTask*` scoping:** scoped grant first, verified by test in task 3.3. Fallback and residual risk are documented in this doc §7.2.
- Encryption at rest (per `security-compliance`): one customer-managed KMS key with rotation enabled, used for the DynamoDB table (`SSEType: KMS`), the SNS topic, and the callback DLQ. The key policy grants `cloudwatch.amazonaws.com` and `events.amazonaws.com` only `kms:GenerateDataKey*` and `kms:Decrypt`. This is required anyway, because CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed `aws/sns` key. The S3 bucket uses SSE-KMS with the same key, blocks all public access, has versioning enabled, and has a bucket policy that denies requests where `aws:SecureTransport` is false. CloudWatch Logs use default encryption. In transit: TLS to all endpoints.
- Tags on every resource: `project=network-routing-drift-checker`, `environment`, `owner`, `data-classification=internal`, `agent-managed=true`.
- Bedrock Guardrails: not applicable; the solution invokes no Bedrock model. The DevOps Agent Agent Space's own guardrails apply to the investigation.

## 12. Cost model (§14.3)

Small network, daily cadence, 30 runs/month: Scheduler 30 invocations; Step Functions ~25 state transitions/run → 750/month; Lambda ~15 invocations/run at 512 MB, ~40 s total compute/run; DynamoDB on-demand < 10 k requests/month; S3 < 100 MB stored, < 1 k requests; SNS 30–60 publishes; CloudWatch Logs < 50 MB, 9 alarms in Phase 1 (11 with Phase 3; standard alarms cost USD 0.10 each per month); one customer-managed KMS key (USD 1/month plus request charges, the single largest fixed line item). Everything else sits in or near free tiers. The README states the computed figure (expected under USD 5, KMS included) with the pricing-page links and the assumptions above.

**Measured (tasks.md 4.2, 2026-10-16, lab, us-east-1, list prices from the AWS Price List API):** a scheduled run used 16 state transitions and 10 Lambda invocations (about 15 s at 512 MB), and a run with one investigation batch used 19 and 13. That's about **USD 3.00/month**, within the §14.3 budget. Fixed items dominate: the KMS key (USD 1.00) and the alarms (USD 1.90). Alarms are billed per metric, and the 11 alarms use 19 metrics, because the failed-run alarm's math expression uses 3 and each Lambda error-rate alarm uses 2. The earlier estimate of USD 0.10 per alarm undercounted that. Variable usage is under USD 0.10. DevOps Agent investigations are billed by the Agent Space and fire only on NEW findings.

## 13. Testing strategy (§14)

| Layer | Tooling | What |
|---|---|---|
| Unit: checks, ID, diff, intent, report, HMAC, batching | pytest, recorded fixtures under `tests/fixtures/` (no network, no credentials) | §14.1 matrix: every check × Cloud WAN/TGW × drift/no-drift × edge cases |
| IAM lint | pytest over `cdk synth` output | §14.4 deny-by-default allowlist |
| Secret redaction | pytest | Secret and URL never in logs or state-machine I/O |
| Integration (deployed, test account) | `scripts/smoke-test.sh` | §14.5 ad-hoc run with one Region → SNS message received |
| Operational | scripted against the deployed stack | §14.6 missed-run alarm, skipped-checks line, Region-not-evaluated line |
| Investigation evals | `tests/evals/` harness: replays recorded NEW-finding sets through a test Agent Space with the skill loaded, captures the callback, scores with deterministic graders | §14.7 boundary (regex over whole output), schema (6.3 validator), fallback (fault injection on the webhook: 5xx, timeout, malformed callback), grounding (fixtures with empty CloudTrail/Health → expects "no evidence found" + `low`), grouping (set equality on `member_finding_ids`), ranking (prod incident before dev at equal counts) **v1: deferred to post-v1 (2026-10-16, requirements §11.5); grouping unscored.** |
| Performance | timed smoke runs against two synthetic network sizes (CDK test fixture stack or recorded-latency simulation) | §14.2 |

Eval graders are code, not LLM-as-judge, so eval results are themselves deterministic. If grouping or ranking fall below threshold after skill tuning, §11.5 (root-cause-only) is the recorded fallback and `tasks.md` carries the decision gate.

## 14. Build-phase verification items

| # | Item | Status | Result recorded in |
|---|---|---|---|
| 1 | Callback transport and progress signal (task 0.1) | **Verified 2026-10-13.** EventBridge `aws.aidevops`, zero ingress; correlation via `[INVESTIGATION_ID:…]` in the first journal message; progress events are one-shot | §3.3, §3.4, §7.2, §8, §9, §11 |
| 2 | VIF prefix allocation field (task 0.2) | **Verified 2026-10-13.** `prefixPoolAllocatedCountIpv4` / `prefixPoolAllocatedCountIpv6` | §4.5 |
| 3 | `GetNetworkRoutes` non-installed routes (task 0.3) | **Verified 2026-10-13.** Installed routes only; Cloud WAN backup check is attachment-level, with an informational `hybrid-path-backup-unverifiable` finding | §4.6 |
| 4 | `SearchTransitGatewayRoutes` pagination and filters (task 0.4) | **Verified 2026-10-13** against the botocore model. `Filters` required; `NextToken` plus paginator; split fallback kept | §4.2 |
| 5 | `states:SendTask*` scoped to the state machine ARN | **Verified 2026-10-15** (see end of cell). Was open: authorization reference vs. reference implementation disagree; resolved by the integration test in task 3.3. As synthesized, `grantTaskResponse` emits the three actions on the state machine ARN (no `*`). **Verified live 2026-10-15:** `SendTaskHeartbeat` (first run) and `SendTaskSuccess` (second run, execution `handoff2-20261015T132846`) both succeeded under the grant scoped to the state machine ARN. The scoped grant stays; no `*` fallback and no residual-risk statement needed | §7.2 |
| 6 | Cross-account event delivery: resource-policy principal (role ARN vs account), and `aws.aidevops` events reaching a cross-account Lambda target | **Verified live 2026-10-15** (two separate AWS accounts, D = Agent Space account, N = networking account, us-east-1). With account D as the callback's resource-policy principal, the companion rule delivered all three events of one investigation (`Created`, `In Progress`, `Completed`) to the callback in N: rule `Invocations` 2 in the first hour, `FailedInvocations` 0. The callback assumed the journal reader and correlated the batch from the first journal message | §3.3a, §7.2 |
| 7 | What `AIDevOpsAgentAccessPolicy` covers for the secondary-source role in N (Network Manager, TGW, DX, CloudTrail, Health) | **Verified 2026-10-15, policy version v11:** covers `cloudtrail:LookupEvents`, the three `health:Describe*` reads, `networkmanager:GetCoreNetwork`/`GetCoreNetworkPolicy`/`ListAttachments`, all TGW reads incl. `SearchTransitGatewayRoutes` and route-table associations/propagations, `ec2:DescribeVpnConnections`, and the DX VIF/gateway/association reads. **Not covered:** `networkmanager:GetNetworkRoutes` (needed for Cloud WAN route evaluation) and `networkmanager:GetCoreNetworkChangeEvents`. The task 3.8 snippet adds only those two | §3.3a, requirements §15 |

Items 2–4 were verified against the botocore 1.43.111 service models. **Live recording, 2026-10-13** (non-production lab account, read-only, sanitized, stored as `tests/fixtures/recorded/raw_responses.json`) results:

- **Confirmed live:** `SearchTransitGatewayRoutes` with the required `state` filter on 8 route tables; a blackhole route carries no `TransitGatewayAttachments`; `GetNetworkRoutes` and `GetCoreNetworkPolicy(Alias=LIVE)`; `DescribeDirectConnectGateways` returning the same global list from every Regional endpoint.
- **Learned live, folded in:** Network Manager uses a single us-west-2 endpoint (requirements §9.1, D§2.1), and DX gateways are global, so discovery uses each association's Region (requirements §9.1).
- **Not observable in the lab** (no VIFs, no DX associations, no Cloud WAN attachments, no table over 1,000 routes): the `prefixPoolAllocatedCount*` fields (item 2), the capped-pagination fallback (item 4), and Cloud WAN route destinations. These paths are covered by Stubber fixtures validated against the pinned model. They are re-checked live when an account with those resources is available, which is tracked under task 1.14.

## 15. Open trade-offs recorded

- **Static limits are hard-coded in the registry** with doc URLs rather than read from Service Quotas, because the limits that matter here are not exposed there. The README tells customers how to override a limit if they have a raised quota.
- **Route counts for the on-prem→AWS allocation are inferred** from installed routes, which undercounts if the customer filters inbound prefixes. Labeled as an approximation in the finding.
- **Only full-scope runs advance the lookback marker.** A customer who only ever runs ad hoc with overrides will see the lookback grow; the heartbeat shows the marker date so this is visible.
