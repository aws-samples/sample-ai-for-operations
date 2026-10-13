# AWS Health Event Triage Agent — Capability Checklist (Master Spec)

<!-- ticket: TEAM-1234 -->

> **Status:** v1 approved at the end of Ideation. High-level checklist for the whole solution. Each phase is delivered through
> one or more disposable working specs under `.kiro/specs/_working/<change-name>/`, which the Build
> agent drives and the Release agent archives. Items stay unchecked until the user validates them;
> "pending-review" findings, not this file, record that code was written.
>
> Ordering rule: Phase 0 and Phase 1 first. Phase 1b (DevOps Agent incident gate) may start as soon
> as Phase 1 lands, because the incident gate uses only native event fields (category, status, scope,
> affected accounts) and publishes outcomes through the minimal SNS notification delivered in Phase 1.
> Phases 2 and 3 complete the core. Phase 5b (readiness gate) depends on Phase 3 (inventory and
> tickets). Phase 6 depends on Phase 5b.
>
> **Cross-phase delivery note (`feat-deploy-triage-workflow`, resolved after Phase 1b):** a
> long-standing gap flagged in every phase's finding since Phase 5 — `infra/bin/app.ts` never
> instantiated `TriageWorkflowStack`/`DigestStack`, so nothing built in Phases 2-5 or 1b was actually
> deployable — is now resolved. `TriageWorkflowStack` builds its own Python Lambda functions (worker,
> classifier, inventory, and, when `-c enableDevOpsAgentGate=true`, the DevOps Agent gate + callback
> functions) via Docker-bundled `PythonFunction`; a new `HealthTriageLeafFunctionsStack` holds the
> intake and digest functions. `cdk synth` verified end-to-end for both the default and
> gate-enabled configurations, including a cross-stack KMS-key-policy grant cycle and a
> Lambda/state-machine grant cycle discovered and resolved during Build (see the inline
> comments in `infra/lib/triage-workflow.ts` and `infra/lib/python-lambda.ts` for how each
> was resolved).

## Phase 0 — Foundation and hygiene

Working spec: `chore-master-spec-alignment`

- [ ] Rename the solution and package to `aws-health-event-triage-agent` / `src/`; remove "PHD" and
      "Personal Health Dashboard" from identifiers, resource names, prompts, and docs (R18)
- [ ] Adopt the standard project layout from `design.md` §8; carry forward surviving Hypothesis
      property tests
- [ ] Archive the six legacy specs to `.kiro/archive-specs/<name>/` with breadcrumbs in
      `.kiro/archive-specs/README.md` (date, what shipped, "master spec created: yes")
- [ ] `src/config.py` as the only reader of environment; seed-file loading via CDK custom resource
      with placeholder-only examples (R15)
- [ ] Amazon Bedrock Guardrails resource and wiring into the classifier (R16.1)
- [ ] KMS keys with rotation; encrypted SQS, SNS, DynamoDB with PITR; `agent-managed` tags (R16.6)
- [ ] Structured JSON logging keyed by `eventArn`; X-Ray on all compute; `HealthTriage` metric
      namespace and alarms (R17)
- [ ] README, QUICKSTART, SECURITY updated for the new architecture; `.crux`/CI unchanged unless needed

## Phase 1 — Ingestion on AWS Health organizational view

Working spec: `feat-health-org-view-ingestion`

> **Delivery note (2026-09-28, working spec `feat-devops-agent-enrichment` §1b/§3.0, "Phase −1", tasks
> −1a/−1b):** a pre-existing defect in this phase's idempotency design was found and fixed ahead of
> the rest of that working spec, because it stood alone and needed to ship first. The idempotency key
> below is corrected from `(eventArn, lastUpdatedTime)` to the feed's real per-message granularity,
> and the workflow start moved from the Intake Lambda itself to a new settle-window consumer Lambda
> (SQS delay queue) so it never starts against a record still mid-fan-out. Both items below are struck
> through in favour of the corrected line; the rest of this phase's checklist is unaffected and its
> status is unchanged by this note. See master `design.md` §3.1 and `requirements.md` R2.1/R2.6 for the
> full corrected wording.

- [ ] StackSet A: `aws.health` EventBridge rule in every enabled Region of the Health admin account →
      central bus with resource policy (R1.1–R1.2)
- [ ] Central bus → SQS (KMS, DLQ) → Intake Lambda with partial-batch failure reporting (R1.7)
- [ ] Native schema parser replacing the AHA-shaped `event_parser.py`: `affectedAccount`,
      `eventScopeCode`, `latestDescription`, `page/totalPages`, `actionability`, `personas` (R1.3–R1.4)
- [x] ~~Idempotency on `(eventArn, lastUpdatedTime)`~~ → Idempotency on
      `(eventArn, affectedAccount, lastUpdatedTime, page)` — the feed's real per-account, per-page
      granularity; `merge_event_message` precision function with property tests for idempotence and
      order-independence (R2.1, corrected)
- [ ] Account context enrichment with cache and `Environment_Type` derivation (R3)
- [x] ~~Idempotent `TriageWorkflow` start per update (design §3.1)~~ → Settle-window consumer Lambda
      (SQS delay queue, `INTAKE_SETTLE_SECONDS` default 60s) is now the sole caller of
      `StartExecution`, using the same fixed execution name; the Intake Lambda only enqueues (R2.6,
      design §3.1)
- [ ] Retire the AHA stack and document prerequisites (org view, delegated admin, Support plan) (R1.6)
- [ ] Optional reconciliation Lambda from a `lastUpdatedTime` watermark (R1.5)
- [ ] Minimal notification path so events are visible before classification exists:
      `NotificationPayload v1` schema (classification fields nullable until Phase 2), `SnsSink`,
      `TicketMap` with in-place update by `eventArn` (R11.1–R11.3)
- [ ] `AuditLog` write on every path; workflow Catch → Audit (R6.6)
- [ ] Integration test: N account messages + multi-page entities for one ARN → one record, one SNS
      create, N−1 in-place updates (R2, R11)

## Phase 1b — Optional module, first increment: AWS DevOps Agent incident gate

Working spec: `feat-devops-agent-incident-gate` (may run in parallel with Phase 2)

> **Delivery note (updated, second Build round):** application code, unit tests (123 tests), the Step
> Functions ASL wiring, the Agent Space CDK construct + webhook-provisioning custom resource, and
> StackSet C are all built and verified (`cdk synth`/`tsc --noEmit` clean, full test suite 729
> passed, esbuild-bundled Lambda asset confirmed at 492.5kb). Still deferred: deploying
> `workflow_handler.py`/`callback_handler.py` as real Lambda functions (blocked on the pre-existing
> `app.ts` Lambda-asset-bundling gap that also blocks `TriageWorkflowStack`/`DigestStack`), the
> optional journal-poll fallback, and the `ASSUME_ROLE` trigger method (no confirmed API). See
> `README.md`'s Phase 1b section for the full breakdown.

- [x] Confirm DevOps Agent API operations for trigger, list active investigations, add context, journal
      read; pick `WEBHOOK` vs `ASSUME_ROLE` default (design §13.1) — confirmed against the reference
      implementation and the installed boto3/botocore `devops-agent` service model; `WEBHOOK` is the
      default and only fully implemented method
- [x] `AgentSpaceRegistry` schema, placeholder seed, and resolver (account+tag → account → OU → default) (R12.6)
- [x] Incident gate as `decide_investigation` precision function on native fields only
      (`eventTypeCategory`, `statusCode`, `eventScopeCode`, `eventTypeCode` allow-list, affected
      accounts) with table-driven tests over policy × category × scope × status × counters × active
      investigations (R12.2, R12.4)
- [x] Duplicate check against active investigations with `dedupe: local_only` fallback (R12.5)
- [x] Monthly `Counters` with conditional increments and cap metrics (R12.8)
- [x] Trigger via webhook (secret from Secrets Manager) (R12.6) — [ ] via cross-account role: not
      implemented (no confirmed non-webhook trigger API; explicit `NotImplementedError` stub)
- [x] ~~StackSet C: `aws.aidevops` forwarding rule (+ optional `DevOpsAgentTriggerRole`, gated behind a
      parameter since no confirmed `ASSUME_ROLE` API exists) in owner accounts~~ → **deleted 2026-09-28,
      working spec `feat-devops-agent-enrichment` (Phase B, R12.9)** — the reference deployment now
      co-locates every Agent Space in the operations account by default, so `aws.aidevops` events reach
      the central bus's own callback rule directly with no forwarding hop; see Phase 3's note above
- [x] `waitForTaskToken` wait state with timeout (R12.7) — [ ] heartbeat: not applicable, no confirmed
      heartbeat signal exists in the DevOps Agent API — [x] callback Lambda — [ ] journal-poll fallback:
      deferred, tracked follow-up (R12.7)
- [x] `summarize_investigation_outcome` rule-based mapping to `impact` enum; outcome folds into the
      existing ticket in place via the Phase 5 `dispatcher.dispatch()` (R12.7, R11.2) — note: uses the
      existing sink dispatcher directly rather than a parallel SNS-only `TicketMap` update path, since
      Phase 5 already generalized ticket updates across all sinks
- [ ] Documentation: per-space policy guidance for customers whose monitoring already triggers
      DevOps Agent; one-space-per-environment recommendation (R12.4, R12.9) — partially done in
      README.md; full customer-facing guidance still pending the deferred infra pieces above

## Phase 2 — Classification, urgency, disposition, prechecks

Working spec: `feat-classification-and-disposition`

- [ ] Classifier reduced to the R4 role as a Strands-on-Lambda Step Functions task (2 GB, 10-min
      timeout, ARM64 container): prompt in `src/prompts/classifier.md`, S3 override,
      `ClassificationResult` schema validation, retry-then-`UNCLASSIFIED`; retire AgentCore Runtime
      and AgentCore Gateway (R4, R15.2, design §2)
- [ ] Agent tools `get_event_type_guidance`, `get_affected_entities`, `normalize_dates` (design §5)
- [ ] `EventTypeGuidance` seed for the known event-code families (design §3.3)
- [ ] `compute_urgency` precision Lambda with configurable thresholds and recomputation on update (R5)
- [ ] `decide_disposition` with `DispositionOverrides` seed marking maintenance-class and confirmation
      codes `DIGEST` (R6.1–R6.3)
- [x] ~~Precheck framework and `msk_patch_safety` (CloudWatch + open RF=minISR correlation) (R7.2)~~ →
      **deleted 2026-09-28, working spec `feat-devops-agent-enrichment` (Phase B)** — superseded by the
      DevOps Agent investigation's skill-described checks (design §3.5)
- [x] ~~`fargate_posture` precheck behind the optional Kubernetes read path; `not_checked` without it
      (R7.2, R7.4)~~ → **deleted**, same working spec, same reason
- [ ] Optional `aws.eks` "EKS Fargate Pod Scheduled Termination" rule → synthetic `TICKET` (R7.3)
- [ ] Digest Lambda on EventBridge Scheduler with watermark and audit of included ARNs (R6.5)
- [ ] Populate the classification fields of `NotificationPayload v1` (nullable since Phase 1) (R11.1)
- [ ] EvalKit run for R4.3 rules, deadline extraction, injection resistance, `toolcallingaccuracy`

## Phase 3 — Impact inventory, cost, routing, tickets

Working spec: `feat-inventory-routing-lifecycle`

> **Superseded and deleted 2026-09-28, working spec `feat-devops-agent-enrichment` (Phase A/Phase B —
> task 18/19/20 of that working spec's own tasks.md; also see the note at Phase 5b above).** The two
> items below (StackSet B and the three per-service inventory plug-ins) describe this phase's original
> design — kept here, marked, rather than deleted, per this file's own established convention of
> recording what changed and why instead of rewriting history. Deadline-class enrichment (R8.2) now
> runs as a DevOps Agent investigation through the same gated webhook-and-callback mechanism Phase 1b
> built, replacing the per-service `sts:AssumeRole` plug-ins; `HealthTriageReadOnlyRole` and StackSet B
> were **deleted from the codebase** once Phase A's live-validation gate condition was met (see the
> `pending-review` finding for the live-validation evidence and the actual Phase B deletion record).
> `build_impact_inventory` itself gains one change (R8.3's impact-locus-qualified status derivation, a
> new `in_scope_unverified` value) — see `design.md` §3.4 for the redesign and `requirements.md` R8 for
> the corrected requirement text. `project_cost` (below, R9) is **not** modified.
- [x] ~~StackSet B: `HealthTriageReadOnlyRole` in member accounts with the §6 read-only policy and
      `aws:PrincipalOrgID` trust~~ → **deleted** by `feat-devops-agent-enrichment` (Phase B), per the
      note above
- [x] ~~Inventory plug-ins `eks.py`, `rds.py`, `lambda_.py`~~ → **deleted** by
      `feat-devops-agent-enrichment` (Phase B); `build_impact_inventory` with `Impact_Status` and
      environment breakdown (R8) kept and revised, per the note above
- [ ] Entity-resolution tracking → auto-close when all entities resolved (R8.5, R11.2)
- [ ] Cost projection per design §3.4.1: `get_pricing` on the Price List Query API with `PricingCache`
      and config overrides; checked-in instance-class → vCPU map; service pricing models for EKS
      (cluster-hour increment), RDS/Aurora (vCPU-hour with year tiers, replicas, Multi-AZ), OpenSearch
      (NIH), ElastiCache (premium %); `project_cost` with assumptions and confidence; unit tests against
      fixture prices; `CostHistory` (R9)
- [ ] Optional: `get_usage_baseline` via Cost Explorer for generic pricing-change notices and
      `reconcile_cost_actuals` against `ExtendedSupport` usage types once charges start (R9.4, R14)
- [ ] Inventory plug-ins `elasticache.py`, `opensearch.py` for the cost-bearing extended-support
      services (R8.2)
- [ ] Correct the extended-support guidance seed: EKS extended fee $0.60/h is inclusive of the $0.10
      standard fee (increment $0.50/h, 730 h/month); the model never states cost figures (R4, R9)
- [ ] `RoutingTable` with precedence tag → account/OU → service → default; documented format (R10)
- [ ] Route-aware notification: per-team SNS topics from `RoutingTable`; close semantics on event
      close or full entity resolution; integration test: 1 create, k updates, 1 close (R11.2–R11.3)
- [ ] Optional `JiraSink`; optional `SlackSink` / `TeamsSink` with secrets from Secrets Manager (R11, R16.3)
- [ ] History retention and reporting queries (R14)

## Phase 4 — Security review and documentation alignment

- [ ] IAM review against `iam-permission-boundary`: no mutating actions, ARN-scoped writes with tag
      conditions, no `Resource: "*"` on writes (R16.2)
- [ ] Threat model and SECURITY.md refresh: untrusted event text, webhook secrets, cross-account roles (R16)
- [ ] `MUTATING_ACTIONS.md` present only if any mutating tool code exists (R13.2)
- [ ] README warning block for optional write actions, if applicable
- [ ] Master spec `requirements.md` / `design.md` reconciled with what was built (spec-model rule 4)

## Phase 5b — Optional module, second increment: AWS DevOps Agent readiness gate

Working spec: `feat-devops-agent-readiness-gate` (after Phase 3)

> **Delivery note:** built as a new, independent `decide_readiness` precision function
> (`src/devops_agent/readiness_gate.py`) rather than folded into `decide_investigation` — R12.3's
> criteria (per-account tracking, prior-assessment set-difference, separate cap) have no incident-gate
> analogue, and merging the two would have complicated the already-tested incident gate's order for a
> feature not every deployment enables. Runs as a parallel Step Functions branch off the same
> `ResolveAgentSpace` state, per design.md §3.2's mermaid diagram. "Forced change" has no dedicated
> classifier signal in this codebase (confirmed against `classification_result_v1.json`) — read as
> "carries a deadline" for `BREAKING_CHANGE`, mirroring `SECURITY_RELATED`'s own deadline clause in
> the same R12.3 sentence; flagged for replacement if a real forced/advisory signal is ever added.
> Full test suite 827 passed; `cdk synth`/`tsc --noEmit` clean for both default and
> `enableDevOpsAgentGate=true` contexts. See README.md's Phase 5b section for the full breakdown.
>
> **Superseded and deleted 2026-09-28, working spec `feat-devops-agent-enrichment` (Phase A/Phase B):**
> the readiness question this phase answers via a *second* investigation and its own `Parallel` Step
> Functions branch is now answered by the **Phase 3 enrichment investigation** instead — one
> investigation per deadline-class event asks both "what is affected" and "is this change ready to
> make," via a `## Readiness` section on the same callback, rather than two separate webhooks. The
> separate readiness monthly cap is retired (the single per-space incident cap now covers both).
> **What this phase built is NOT deleted along with the second webhook:** `decide_readiness`
> (`readiness_gate.py`), `readiness_tracker.py`, the `ReadinessAssessments` table, and
> `readiness_outcome.py` are all kept, unchanged — the durable per-(event, account) record they
> maintain is what the grown-affected-set re-run (R12.3's last clause) still needs, and nothing else
> in this codebase can answer "which accounts are new since the last assessment" without it. Only the
> *second webhook path* — `TriggerReadiness`'s `.waitForTaskToken` state, `DecideReadiness`,
> `SummarizeReadiness`, the readiness `Parallel` branch, and their Pass states in
> `triage-workflow.ts` — was **deleted**, once Phase A's new path was live-validated and the per-account
> coverage gate confirmed met (see the `pending-review` finding for both the live-validation evidence
> and the Phase B deletion record).

- [x] Readiness gate as `decide_readiness`: requires R8 `impact: confirmed`, class `BREAKING_CHANGE`
      or `SECURITY_RELATED` with a deadline ("forced change" proxy — see delivery note), deadline
      within `READINESS_HORIZON_DAYS`, no prior assessment for (event, account); grown affected set
      re-triggers only for the newly-added accounts, status-only updates never (R12.3)
- [x] ~~Separate monthly readiness cap and metrics (`get_readiness_counter`/`increment_readiness_counter`,
      distinct `readinessCount` attribute on the shared `AgentSpaceCounters` table) (R12.8)~~ →
      **`increment_readiness_counter` deleted** by `feat-devops-agent-enrichment` (Phase B); the single
      per-space incident cap now governs all enrichment investigations (R12.8 revision, see the note
      above). `get_readiness_counter` kept, re-purposed for the enrichment-kind readiness check.
- [x] Readiness assessment webhook payload (`build_readiness_webhook_payload`, reusing the incident
      gate's signing/eventType contract unchanged) and a new, generic (not EKS-specific) Custom Skill
      (`devops-agent-skill/readiness-assessment/SKILL.md`) modeled on the AWS lifecycle-upgrade
      sample's flat `FEASIBILITY`/`BLOCKERS`/`RISK`/`ROLLBACK_AVAILABLE` output contract (R12.3)
- [x] Longer `waitForTaskToken` timeout profile for assessments (24 h default,
      `DEVOPS_AGENT_READINESS_WAIT_TIMEOUT_HOURS`) (design §3.2)
- [x] Assessment outcome folded onto the `NotificationPayload` alongside (not instead of) the incident
      gate's `impact`/`investigationLink` — `readinessFeasibility`/`readinessBlockers`/`readinessRisk`/
      `readinessAssessmentLink`, both may be present simultaneously (R12.7, R11.2)
- [x] `callback_handler.py` now dispatches on a `kind: "incident"|"readiness"` tag stored on the task
      token record, so one callback path serves both gates with the correct outcome parser

## Phase 6 — Optional module: PR-based remediation

Working spec: `feat-pr-based-remediation`

- [ ] Hand-off of readiness change spec to the PR-generation step following the AWS lifecycle-upgrade
      sample; human merge only (R13.1)
- [ ] Retire the legacy runtime EKS upgrade approval path (R13.3)
- [ ] Verify no mutating AWS permissions shipped; update `MUTATING_ACTIONS.md` if any tool code could mutate

## Phase 7 — Evaluation and release readiness

- [ ] Synthetic labelled eval set from public `eventTypeCode` values covering every family in
      `requirements.md` §6, the R4.3 disambiguation cases, status transitions, multi-page events, and
      adversarial descriptions; no customer data
- [ ] EvalKit run (`@agent-sop:eval`) with `evaluation_focus` derived from R4, R5, R8.3 and
      `toolcallingaccuracy`; per-requirement reliability table in `eval/eval-report.md`
- [ ] Deterministic test suite green: unit, property, integration, gate tables
- [ ] Success-criteria check against `requirements.md` §10 on the first deployment's metrics over the
      pilot period (digest ratio, one ticket per ARN, latency, caps, zero DLQ residue)
- [ ] Release gate: master spec true, working specs archived, no customer data in repository or eval
      report, `pending-review` findings graduated by the user

## Evals for hand-off, hard boundaries, success criteria

Defined once in `requirements.md` §9–§11 and `design.md` §10–§12; this checklist references them
rather than restating. Build must not mark a phase complete until the tests listed for that phase
pass and the corresponding requirement rows appear in the eval report.

## Eval testing framework

- Deterministic components: `pytest` + `hypothesis` (property tests) + `moto` (AWS stubs) under
  `tests/`, run by `make test`.
- Language-model behaviour: EvalKit on the Strands Evals SDK (`@agent-sop:eval`), artifacts in `eval/`
  (sibling of `src/`); only the scrubbed `eval/eval-report.md` ships.
- Gate and routing logic: table-driven tests generated from the seed configuration files so that the
  shipped defaults are themselves tested.
