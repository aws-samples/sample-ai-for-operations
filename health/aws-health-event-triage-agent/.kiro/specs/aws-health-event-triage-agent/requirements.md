# AWS Health Event Triage Agent — Requirements (Master Spec)

> **Status:** v1 approved by the solution owner at the end of Ideation. This is the master spec: the
> single source of truth for what this solution does and why. It supersedes the six legacy specs written under the previous framework
> (`phd-notification-classifier`, `aha-eventbridge-lambda`, `agentcore-gateway-mcp`,
> `auto-routing-config`, `jira-ticket-creation`, `human-approval-remediation`), which are to be archived
> to `.kiro/archive-specs/` during Build. Where this document and the code disagree, this document
> states the intended behaviour.
>
> **Phase delivery status (updated 2026-09-27):**
> - **Phase 0 complete** — `chore-master-spec-alignment`: repository layout, naming, `src/config.py`, CDK baseline (CoreStack + GuardrailStack), legacy spec archive. See design §8.
> - **Phase 1 complete** — `feat-health-org-view-ingestion`: native EventBridge intake (parser, merge, Intake Lambda + handler, TriageWorkflow skeleton, StackSet A template, SnsSink + TicketMap, NotificationPayload v1). See design §3.1.
> - **Phase 2 complete** — `feat-classify-and-triage`: Strands-on-Lambda classifier with three agent tools (`get_event_type_guidance`, `get_affected_entities`, `normalize_dates`), `compute_urgency` and `decide_disposition` precision tools, ClassificationResult v1 schema with JSON-validation and UNCLASSIFIED fallback, EventTypeGuidance + DispositionOverrides seed data, TriageWorkflow updated (LoadEvent → Classify → ComputeUrgency → DecideDisposition → Notify → Audit), NotificationPayload v1 extended with classification/urgency/deadline/disposition fields. See design §3.2, §3.3, §5.
> - **Phase 3 complete** — `feat-inventory-and-cost`: read-only inventory plug-ins (`describe_eks_readiness`, `describe_rds_readiness`, `list_lambda_functions_by_runtime`), `build_impact_inventory` precision aggregator with confirmed/not_detected/unverifiable Impact_Status, `get_pricing` (Price List API + cache + config override), `map_instance_class_to_vcpu`, `project_cost` precision function (EKS increment + RDS vCPU-hour models), dedicated Inventory Lambda handler with assume-role degradation, TriageWorkflow extended with a `Choice`-gated Inventory → ProjectCost branch, NotificationPayload v1 carrying `impactSummary`/`costProjection`. See design §3.4, §3.4.1, §5. HealthTriageReadOnlyRole (StackSet B) deployment tracked as a follow-up working spec.
> - **Phase 4 complete** — `feat-digest-and-prechecks`: `fargate_posture` and `msk_patch_safety` prechecks (pure code, read-only, `not_checked` when the optional Kubernetes/MSK read paths are absent), a precheck runner dispatcher, `escalate_on_precheck_failure` (DIGEST + fail → TICKET naming the failing resources), `format_digest` precision function grouping by event family and account, a scheduled Digest Lambda (watermark → query → format → publish → advance → audit, never advancing the watermark on failure), TriageWorkflow extended with a `Choice`-gated RunPrechecks branch, and an EventBridge Scheduler + digest SNS topic + `byDispositionUpdatedAt` GSI in CDK. See design §3.4, §3.8, §5. The Kubernetes EKS access entry and MSK CloudWatch metric wiring are tracked as follow-ups — prechecks degrade to `not_checked` (visible in the digest) until those read paths are provisioned.
> - **Phase 5 complete** — `feat-routing-and-sinks`: StackSet B (`HealthTriageReadOnlyRole`, read-only by construction, `aws:PrincipalOrgID` trust), `resolve_team` (tag → account/OU → service → default precedence), `should_close` (auto-close on `statusCode=closed` or all entities resolved), a common `Sink` interface with `SnsSink` retrofitted and `JiraSink`/`SlackSink`/`TeamsSink` added (HTTPS-only, credentials from Secrets Manager by ARN), and a sink dispatcher with per-sink failure isolation wired into a newly-built worker Lambda handler that also closed a gap from Phase 2 (the `LOAD_EVENT`/`COMPUTE_URGENCY`/`DECIDE_DISPOSITION`/`NOTIFY`/`AUDIT` steps had no Python implementation until now). See design §3.5, §6, §5. `infra/bin/app.ts` still does not instantiate `TriageWorkflowStack`/`DigestStack` (Lambda asset-bundling is deployment-phase work) — tracked as a follow-up.
> - **Phase 1b complete** — `feat-devops-agent-incident-gate` + `feat-deploy-triage-workflow`: the AWS DevOps Agent incident gate (R12.1-R12.2, R12.4-R12.8), including the `AgentSpaceRegistry` resolver, `decide_investigation`, webhook trigger/signing, dedupe, monthly counters, the `aws.aidevops` EventBridge callback handler, the Agent Space CDK construct + webhook-provisioning custom resource, StackSet C, and the `app.ts` gap resolution that made the whole `TriageWorkflow` state machine (and this module) actually deployable via `cdk synth`. See design §3.2, §3.6, §7.
> - **Phase 5b complete** — `feat-devops-agent-readiness-gate`: the readiness gate (R12.3, R12.8's separate readiness cap) as an independent `decide_readiness` precision function, run as a **parallel** Step Functions branch off the same `ResolveAgentSpace` state as the incident gate (design §3.2's mermaid diagram: `Notify <- IncidentGate`, `Notify <- ReadinessGate`) rather than folded into `decide_investigation` — R12.3's per-account tracking and prior-assessment set-difference logic have no incident-gate analogue. Reuses the incident gate's webhook signing, `.waitForTaskToken`, and `aws.aidevops` callback mechanism unchanged (no separate "readiness" `eventType` exists); `callback_handler.py` now dispatches on a `kind: "incident"|"readiness"` tag on the task-token record to pick the right outcome parser. Ships a second, generic (not EKS-specific) Custom Skill (`devops-agent-skill/readiness-assessment/SKILL.md`). **Interpretation note:** this codebase has no dedicated "forced vs advisory" classifier field (confirmed against `classification_result_v1.json`), so R12.3's "class `BREAKING_CHANGE` with a forced change" is implemented as "carries a deadline" — mirroring `SECURITY_RELATED`'s own deadline-gated clause in the same requirement sentence. A future working spec adding a genuine forced/advisory signal should replace this proxy. See design §3.2, §3.6.
> - **Repository cleanup complete** (`chore-legacy-code-removal`, no working spec — pure deletion/doc-fix, no behavior change): removed every pre-refactor artifact that Phase 0's rename (`chore-master-spec-alignment`) had copied into `legacy/` or left duplicated at the repository root but never actually deleted or stopped referencing from build/test tooling. Deleted: the root duplicates of `approval_lambda/`, `routing_approval_lambda/`, `routing_config_lambda/`, `aha_eventbridge_lambda/`, `phd_notification_classifier/`, the whole `legacy/` directory, `deploy.sh`, `Dockerfile` (both were the pre-CDK SAM/AgentCore-Runtime deploy path), `docs/` (`roadmap.md`/`deployment.md`/`integrations.md`, all AHA/AgentCore-Gateway era), the pre-refactor `security/` docs (`DESIGN.md`, `SECURITY_GUIDELINES.md`, `accepted-risks.csv`, `bedrock-model-approval.md`, `scan-results/*`), and — inside `src/` itself — the still-imported but pre-Phase-2 Bedrock AgentCore Runtime entry point `src/agent.py` plus the four legacy-only tool modules only it reached (`src/gateway_tools.py`, `src/prompts.py`, `src/sinks/sns_notifier.py`, `src/intake/impact_analyzer.py`) and their dedicated tests. Two files (`src/inventory/eks.py`, `src/cost/project_cost.py`) contained one legacy function alongside one still-used current function under similar names (`describe_eks_cluster` vs `describe_eks_readiness`; `estimate_cost` vs `project_cost`) — only the legacy halves were removed, confirmed function-by-function via import-graph search before touching either file. `SECURITY.md` was also removed at the user's request — the whole threat model predated this rename and described the deleted architecture; it will be regenerated fresh for the current system in a future working spec. Modernized `security/SCAN_PROCESS.md` in place (its content is still referenced by every `src/` file's copyright header) rather than deleting it. Fixed every dangling reference this left in `Makefile`, `infra/lib/python-lambda.ts`, `README.md`, `QUICKSTART.md`, and `MUTATING_ACTIONS.md` (which had documented a mutating tool, `upgrade_eks_cluster`, that was never actually shipped in any reachable code path). Test suite: 619 passing (down from 827 at the point Phase 5b was delivered — the difference is entirely the deleted legacy test suites, not a regression); `make lint-terms` and `cdk synth`/`tsc --noEmit` (both contexts) all clean. No src/ file that the current classifier/inventory/devops_agent/triage/sinks pipeline actually imports was touched.
> - **First live build validation complete** (`feat-claude-sonnet-5-model-update`, no separate working
>   spec — model config change plus bug fixes surfaced by the deploy itself): switched the default
>   classifier model to Claude Sonnet 5 (`eu.anthropic.claude-sonnet-5`, inference-profile-prefixed —
>   confirmed via `aws bedrock list-inference-profiles` that the bare model ID is not directly
>   invokable in eu-west-1). Then ran this solution's first-ever real `cdk deploy` (sandbox account
>   123456789012, eu-west-1; `enableDevOpsAgentGate` not enabled), which found and fixed five real
>   bugs invisible to `cdk synth`-only validation, all corrections back to already-documented intent
>   rather than new intent: a recursive Lambda asset-copy crash in `python-lambda.ts`; an invalid IAM
>   principal from a default `healthAdminAccountId='*'`; a missing KMS grant for CloudWatch Logs; a
>   real CDK-detected circular dependency from a dead `grantStartExecution` call; the `Classify` state
>   wired to the wrong Lambda (`workerFunction` instead of `classifierFunction`, contradicting the
>   `LoadEvent → Classify → ComputeUrgency → DecideDisposition` design already specified in Phase 2);
>   and a systemic Step Functions `Pass`-state bug where literal `null` values are silently dropped by
>   `aws-cdk-lib`'s renderer (previously fixed only for the Phase 5b readiness fields, now fixed
>   workflow-wide via a `SeedNullDefaults`/`nullDefaults.$` threading pattern). See design's Phase 5
>   delivery note's sibling "Build validation note" for full detail. Three real test events were run
>   through the deployed pipeline; the third completed `LoadEvent → ... → Notify → Audit → SUCCEEDED`
>   end-to-end with a genuinely-reasoned classification. `enableDevOpsAgentGate=true` and a
>   non-`UNCLASSIFIED` classification path (e.g. `BREAKING_CHANGE`) remain unvalidated live — tracked
>   as a follow-up before Phase 7.
> - **`feat-devops-agent-enrichment` live-validated and Phase B complete** (working spec, continued
>   session, same day): task 14's Map-based multi-space fan-out live-validated against a real second
>   Agent Space and a synthetic second account — real classification, real per-account-to-space
>   resolution grouping into two distinct spaces, two independent real webhook dispatches accepted by
>   the real AWS DevOps Agent service, two distinct task-token records, no account left uncovered.
>   Two more real deploy-ordering bugs found and fixed live (a CloudFormation cross-stack export/import
>   ordering trap needing `cdk deploy --exclusively`; a genuinely stale Lambda deploy that had missed
>   its own already-committed Phase −1 bug fix by several hours). With the per-account coverage gate
>   confirmed met, **Phase B executed**: the per-service inventory plug-ins (`eks.py`/`rds.py`/
>   `lambda_.py`), the maintenance-class prechecks (`fargate_posture`/`msk_patch_safety`/the runner),
>   `HealthTriageReadOnlyRole` and StackSet B, StackSet C, and the readiness gate's own separate
>   second-webhook trigger path are genuinely deleted from the codebase — not merely described as
>   superseded. `readiness_gate.py`/`decide_readiness`, `readiness_tracker.py`, the
>   `ReadinessAssessments` table, `readiness_outcome.py`, and the four `readiness*` payload fields are
>   kept exactly as this file's own E4 requirement (below) specifies. Full evidence, including the
>   live-validation logs/task-token records and the post-deletion test/synth/ASL-reachability
>   re-verification, was recorded during Build; see `eval/eval-report.md` Section 7 for the
>   live-validation narrative and evidence this file's own R12 row (§7) cites.
> - Phase 6 and the reliability eval: see `eval/eval-report.md`. Phase 7 (broader
>   release-readiness synthetic eval set): planned.
>
> This solution is published to aws-samples as a prototype for any AWS Organizations customer. It
> contains no customer-specific data. Customer-specific inputs (routing tables, Agent Space registry,
> thresholds, suppression lists) are deployment-time configuration.

## 1. Purpose

AWS Health tells customers about service events, scheduled changes, and account notifications across
their organization. In a multi-account organization the raw feed is noisy: most events are recurring
AWS-run maintenance or confirmations, a few are urgent deadlines with financial consequences, and a
small number are live operational issues that may or may not affect a given workload.

This agent turns that feed into **actionable, de-duplicated, owner-assigned work items** and a **daily
digest of everything else**, without dropping anything and without letting a language model do
arithmetic or touch customer resources. Where a live issue or a hard deadline needs a topology-aware
impact check, it can delegate that investigation to **AWS DevOps Agent** under strict gates and
budgets.

**Principle (added 2026-09-28, working spec `feat-devops-agent-enrichment`): code decides whether,
when, and where; DevOps Agent finds out what is affected and what to do.** Every deterministic
decision — de-dup, urgency arithmetic, disposition, the investigation gate, routing, ticket lifecycle,
cost arithmetic — stays in code, unconditionally. Where a decision genuinely needs topology-aware,
open-ended reasoning about a customer's own resources (which of them a deadline-class event affects,
what state they are in, whether a planned change is safe to make), that reasoning is delegated to an
AWS DevOps Agent investigation through the same gated, budgeted, webhook-and-callback mechanism R12
already describes for live issues — never to a per-service Lambda plug-in, and never by letting the
language model itself compute, count, or decide.

### What it is not

- It does not replace the AWS Health Dashboard or AWS User Notifications; it consumes the same feed
  and adds triage, ownership, and lifecycle.
- It does not remediate anything by default. Remediation is an optional, human-gated module that
  proposes changes as pull requests.
- It is not an incident-response platform. It hands confirmed impact to the customer's existing ticket
  and notification channels.

## 2. Users

| Persona | What they get |
|---|---|
| Platform / Cloud Centre of Excellence operations (primary) | One ticket per real event with owner, class, urgency, deadline, affected accounts and resources, confirmed impact where possible; a daily digest of the rest |
| Application team on-call | Tickets routed to their team for the resources they own, updated in place as the event evolves |
| Security team | `SECURITY_RELATED` events routed to them with the resources concerned |
| FinOps / engineering managers | `COST_IMPLICATION` events with projected cost per account and organization-wide; trend data from persisted history |

## 3. Use-case validation record (Step 0)

| Filter | Finding |
|---|---|
| 1. Existing AWS service? | AWS Health Dashboard and AWS User Notifications deliver and consolidate notifications but do not classify into action classes, extract deadlines, project cost, run prechecks, route to owners, or maintain ticket lifecycle. Partially solved for *delivery*; the triage layer is not. |
| 1b. AWS DevOps Agent alone? | A DevOps Agent Skill (no code) cannot de-duplicate across accounts, produce digests, manage ticket lifecycle, or route by ownership. DevOps Agent is used as the **investigation engine** for the subset of events where topology-aware impact verification matters (pattern #9c); this agent is the thin, deterministic wrapper. Reasoning recorded in R12. |
| 2. Needs agentic reasoning? | Yes for one step: classifying free-text event descriptions with disambiguation rules (e.g. security fix vs. deprecation as primary driver, cost vs. forced upgrade) and proposing verification steps. Everything else (de-dup, urgency arithmetic, cost, prechecks, routing, gating) is deterministic code. Hybrid architecture. |
| 3. Too narrow? | No. Nine event families, six classes, multiple sinks, multi-account, multi-Region. |
| 4. Too broad? | Constrained: triage and ownership are core; investigation and remediation are optional modules with their own gates. |
| 5. Existing samples? | AWS Health Aware (aws-samples): superseded by the native organizational-view EventBridge feed. `sample-aws-genai-ops-demos/observability/proactive-health-event-impact-analyzer`: reused for DevOps Agent orchestration and routing/tracking patterns; lacks classification, de-dup, digest. `sample-automate-planned-lifecycle-upgrades-with-aws-devops-agent-and-kiro`: reused for readiness assessment and PR-based remediation. `tools-for-devops-agent` `aws-health-report` custom agent: reporting, not triage. None covers the triage layer end to end. |

### 3.1 Relationship to the DevOps Agent Health-triage reference

`sample-aws-genai-ops-demos/observability/proactive-health-event-impact-analyzer` answers "does this
Health event affect my workloads?" by starting an AWS DevOps Agent investigation for every event and
routing the result. This agent answers "what must the organization do about its Health feed, who owns
it, and by when?" and uses DevOps Agent only where an investigation is the right tool. The reference
is the right choice for a small footprint that wants DevOps Agent to look at every event with minimal
code; this agent is the right choice for organizations with tens of accounts that need
de-duplication, digests, ownership, ticket lifecycle, deadline and cost handling, and gated,
budgeted investigations. The two share the DevOps Agent orchestration mechanism (webhook trigger,
`waitForTaskToken`, `aws.aidevops` callback, Agent Space association), which this design reuses and
credits rather than reimplements. Defects found in the reference while designing this agent
(receiving account used instead of `affectedAccount`, no idempotency, no pagination, no status
filter) should be reported upstream so the two samples agree on the basics. The README states this
boundary so customers can choose.

## 4. Scope

### Core (always deployed)

1. Ingestion from the AWS Health **organizational view** feed on Amazon EventBridge, all Regions.
2. Idempotent, organization-wide consolidation of events by event ARN.
3. Account and environment context enrichment from AWS Organizations.
4. Six-way classification with reason, urgency, and deadline.
5. Disposition of every event into **ticket** or **digest**, with deterministic prechecks for
   maintenance-class notices. Nothing is dropped silently.
6. Deterministic impact inventory for deadline-class events and cost projection.
7. Team routing from a configuration table.
8. Notification via Amazon SNS with a stable JSON payload; ticket lifecycle keyed by event ARN.
9. Persisted event history, observability, guardrails.

**AWS DevOps Agent impact verification (added to Core scope 2026-09-28, working spec
`feat-devops-agent-enrichment`, R8/R12 revision).** Enrichment of deadline-class events (R8.2) and
maintenance-class prechecks (R7) now run as DevOps Agent investigations through the same gated,
budgeted mechanism, when an Agent Space registry is configured — not only the live-issue incident gate
R12 originally described. The module as a whole (registry, gate, webhook, caps, duplicate check)
remains **disabled unless configured** (R12.1); when disabled, deadline-class events fall back to the
entity-list-only baseline (R8.3) rather than per-service Lambda plug-ins, which this revision removes
entirely — there is no plug-in fallback to restore.

### Optional modules (feature-flagged, off unless configured)

- **Ticket adapter: Jira** (create / update / close by event ARN).
- **Chat notifications** (Slack, Microsoft Teams).
- **Remediation**: pull-request-based, human-merged, no mutating IAM shipped.

### Out of scope

- Ingesting non-Health sources (APM alarms, CloudWatch alarms) as triggers.
- Executing changes against customer resources at runtime.
- Replacing the customer's ITSM or paging tools.

## 5. Glossary

- **Event**: an AWS Health event identified by its **event ARN**. One event may affect many accounts;
  the organizational feed delivers one message per affected account (and per page of affected
  entities), so many messages map to one event.
- **Consolidated_Event**: the agent's single record for one event ARN: affected accounts, affected
  entities with status, latest description, category, scope, status, timestamps.
- **eventTypeCategory**: AWS value: `issue`, `scheduledChange`, `accountNotification`, `investigation`.
- **eventScopeCode**: AWS value: `PUBLIC` (service-level event in a Region) or `ACCOUNT_SPECIFIC`.
- **Classification**: exactly one of `SERVICE_DISRUPTION`, `BREAKING_CHANGE`, `SECURITY_RELATED`,
  `COST_IMPLICATION`, `INFORMATIONAL`, `UNCLASSIFIED`, evaluated in that priority order.
- **Urgency**: `critical` (deadline ≤ 7 days), `high` (≤ 30), `medium` (≤ 90), `low` (> 90, none, or no
  action).
- **Deadline**: the earliest date on which inaction causes customer impact, extracted from the event
  description; null when none exists.
- **Disposition**: `TICKET` or `DIGEST`. Every Consolidated_Event gets exactly one.
- **Maintenance-class notice**: a recurring AWS-run maintenance notice (e.g. EKS Fargate OS patch
  evictions, Amazon MSK security patching) that needs no customer action when the workload follows the
  service's high-availability guidance.
- **Precheck**: a deterministic, read-only check of the customer's resources that decides whether a
  maintenance-class notice needs action for this customer.
- **Deadline-class event**: a planned lifecycle event, forced upgrade, deprecation, retirement, or
  certificate change with a date by which the customer must act.
- **Impact_Status**: `confirmed`, `not_detected`, `unverifiable`, or `in_scope_unverified` **(fourth
  value added 2026-09-28, working spec `feat-devops-agent-enrichment`, R8.3 revision)**, always with
  the evidence or the verification steps that support it.
- **Impact locus**: whether the entity AWS lists in a deadline-class event **is** the thing that
  breaks, costs, or gets retired (`listed_resource` — entity presence is itself confirmation, e.g. a
  Lambda runtime deprecation) or is merely **in scope pending a dependent AWS cannot see** — a
  client's trust store, negotiated TLS version, or SDK version (`dependent`, e.g. a certificate-
  authority rotation). Read per `eventTypeCode` from `config/event-type-guidance.json`, defaulting to
  `listed_resource` when absent. **(New, same working spec.)**
- **Environment_Type**: `production`, `non-production`, or `unknown`, derived from account tags or OU.
- **Agent Space**: an AWS DevOps Agent workspace owning one or more associated AWS accounts.
- **Agent Space registry**: the deployment-time table mapping affected accounts (and optionally
  workload tags or OUs) to Agent Spaces with their trigger method, policy, and budget caps.
- **Routing table**: the deployment-time table mapping resource tags, accounts/OUs, and services to
  owning teams and their channels.

## 6. Reference event profile (anonymised, for sizing)

Observed in a representative organization of a few dozen accounts across more than ten Regions over
roughly one quarter; rounded. Used only to set defaults and sizing assumptions; every deployment
differs.

- Roughly 200 distinct events and 450 event-account messages per month (≈ 2.3 messages per event).
  Public issues are delivered once per account, so a single Regional incident produces as many
  messages as there are accounts.
- Distinct events by category: about 60% `scheduledChange`, 33% `accountNotification`, 8% `issue`.
- By family: ~40% recurring maintenance, ~20% deadline-class, ~20% "update available" notices whose
  class depends on the description text, ~8% operational issues, the rest confirmations, billing,
  security notices, and resource-health notices.
- About one third of scheduled changes are within 7 days of their start (or already started) when
  last updated; deadline-class events typically carry 90 or more days of notice.
- 85–90% of distinct events touch one account; the top 3% of events (organization-wide broadcasts)
  account for over 40% of messages.

Design consequences: de-duplication and digest are the largest levers; processing latency must be
hours, not days; Region coverage must be complete; the description text must travel with the event.

## 7. Functional requirements

Acceptance criteria use EARS wording. "The Agent" means the whole solution unless a component is named.

### R1. Ingest the AWS Health organizational view feed

**User story:** As a platform operator, I want one organization-wide feed of Health events with no
polling layer to maintain, so that I see every event from every account and Region within seconds.

1. THE Agent SHALL consume AWS Health events (`source: aws.health`) from Amazon EventBridge in the
   organization's management account or a registered AWS Health delegated administrator account with
   organizational view enabled.
2. THE deployment SHALL create an EventBridge rule in **every enabled Region** of that account that
   forwards Health events to one central event bus in the agent's Region, because AWS Health delivers
   events in the Region where they occur and global events in US East (N. Virginia).
3. THE Agent SHALL read the native event fields, including `eventArn`, `eventTypeCode`,
   `eventTypeCategory`, `eventScopeCode`, `service`, `eventRegion`, `statusCode`, `startTime`,
   `endTime`, `lastUpdatedTime`, `affectedAccount`, `affectedEntities[]` (value, status, tags),
   `eventDescription[].latestDescription`, `communicationId`, `page`, `totalPages`, and, when present,
   `actionability` and `personas`.
4. THE Agent SHALL NOT depend on AWS Health Aware or any other intermediate forwarder.
5. THE Agent SHOULD support an optional scheduled reconciliation that calls
   `DescribeEventsForOrganization` (with `DescribeEventDetailsForOrganization` and
   `DescribeAffectedAccountsForOrganization` as needed) from a `lastUpdatedTime` watermark and
   processes any event not already seen.
6. THE documentation SHALL state the prerequisites: organizational view enabled, management or
   delegated administrator account, and a Business, Enterprise On-Ramp, Enterprise, or Unified
   Operations Support plan.
7. IF a message cannot be parsed, THEN THE Agent SHALL record it to a dead-letter queue with the
   failure reason and raise a metric; it SHALL NOT discard it.

### R2. Consolidate and de-duplicate by event ARN

**User story:** As a platform operator, I want one record per real event regardless of how many
accounts it touches, so that a Regional incident produces one ticket, not one per account.

1. THE Agent SHALL treat `(eventArn, affectedAccount, lastUpdatedTime, page)` as the idempotency key;
   a message with a key already processed SHALL be acknowledged and skipped.
   **(Corrected 2026-09-28, working spec `feat-devops-agent-enrichment` §1b/§3.0, task −1a.)**
   AWS Health's organizational-view feed delivers one message per `(affectedAccount, page)` for a
   single AWS update — several messages sharing one `eventArn` and `lastUpdatedTime` arrive within
   seconds of each other, each for a different account or a different page of one account's entity
   list. The original wording, `(eventArn, lastUpdatedTime)`, was at event granularity only: it made
   every message after the first for the same update look like a duplicate of the first and silently
   dropped it, before it ever reached the merge step in R2.2. This is the feed's real granularity, not
   a widening of the key's purpose — a genuine retry (same account, same page, same update) still
   collapses to the same key and is still correctly skipped.
2. THE Agent SHALL maintain exactly one Consolidated_Event per `eventArn`, merging affected accounts,
   affected entities (across all `page`s), status, and the latest description on every new message.
3. WHEN a message for a known `eventArn` carries a newer `lastUpdatedTime`, THE Agent SHALL update the
   Consolidated_Event and re-run disposition and lifecycle actions on the updated record.
4. THE Consolidated_Event SHALL record per-entity status so that resolved entities are tracked
   individually (AWS updates entity status as customers complete actions on planned lifecycle events).
5. THE Agent SHALL emit metrics for messages received, messages de-duplicated, and Consolidated_Events
   created or updated.
6. **(Added 2026-09-28, same working spec, task −1b.)** THE Agent SHALL run the TriageWorkflow exactly
   once per AWS update (`eventArn`, `lastUpdatedTime`), against the Consolidated_Event only after every
   message for that update has had a settle window (`INTAKE_SETTLE_SECONDS`, default 60 seconds) to
   merge — never against a record that may still be accumulating accounts or pages from a fan-out in
   progress. Messages that arrive after the settle window has already started the workflow are R2.3
   updates to the same event, handled exactly as before this addition.

### R3. Enrich with account and environment context

1. WHEN a Consolidated_Event is created or gains an affected account, THE Agent SHALL retrieve for each
   affected account its name, OU path, and tags from AWS Organizations, cached with a configurable TTL.
2. THE Agent SHALL derive Environment_Type from account tags first, then OU path, using configurable
   tag keys and OU name patterns; otherwise `unknown`.
3. IF the Organizations call fails for an account, THEN THE Agent SHALL log the failure, set
   Environment_Type to `unknown`, and continue.

### R4. Classify every event into exactly one class with a reason

**User story:** As a platform operator, I want every event assigned one action class with a plain
explanation, so that my team knows what kind of response it needs and can check the reasoning.

1. THE Classifier SHALL assign exactly one Classification per Consolidated_Event, evaluating classes in
   priority order `SERVICE_DISRUPTION > BREAKING_CHANGE > SECURITY_RELATED > COST_IMPLICATION >
   INFORMATIONAL > UNCLASSIFIED`.
2. THE Classifier SHALL produce a Classification_Reason of at least one sentence referencing specific
   content of the event.
3. THE Classifier SHALL apply these disambiguation rules:
   - An active outage, Regional disruption, or ongoing degradation currently affecting workloads is
     `SERVICE_DISRUPTION`. Resolved or closed events, scheduled maintenance not yet started, and
     restored-redundancy notices are not.
   - A deprecation, API or endpoint removal, end of support with forced upgrade or blocked
     create/update, or any change where inaction causes failure or forced change is `BREAKING_CHANGE`.
   - An event with both a cost increase and an eventual forced change (e.g. extended support then
     auto-upgrade) is `BREAKING_CHANGE`; the cost is reported alongside.
   - An event with both a security fix and a deprecation deadline is `SECURITY_RELATED` if the
     security fix is the primary driver, otherwise `BREAKING_CHANGE`.
   - An optional update with no enforced deadline is `SECURITY_RELATED` if the description cites a CVE
     or security fix, otherwise `INFORMATIONAL`.
   - A financial impact without forced change or breakage is `COST_IMPLICATION`.
   - Renewals, confirmations, successful automatic recoveries, and general advisories are
     `INFORMATIONAL`.
   - Insufficient detail is `UNCLASSIFIED`, never guessed.
4. WHEN the event carries `actionability` or `personas`, THE Classifier SHALL use them as priors and
   SHALL state in the reason when its class disagrees with `actionability`.
5. THE Classifier SHALL treat event text as untrusted data: instructions embedded in a description
   SHALL never change agent behaviour, and the Classifier output SHALL be validated against a JSON
   schema before use.

### R5. Extract deadlines and compute urgency deterministically

1. THE Agent SHALL extract the Deadline as the earliest date on which inaction causes customer impact
   (e.g. when security patches stop, not when creation is later blocked); null when none exists,
   including for `SERVICE_DISRUPTION`, `INFORMATIONAL`, and `UNCLASSIFIED`.
2. A precision tool, not the language model, SHALL compute Urgency from the Deadline and the current
   date using the 7/30/90-day thresholds, configurable per deployment.
3. `INFORMATIONAL` and `UNCLASSIFIED` events SHALL always have Urgency `low`.
4. WHEN a Consolidated_Event is updated, THE Agent SHALL recompute Urgency and SHALL raise it when a
   threshold has been crossed.

### R6. Give every event a disposition: ticket or digest, never dropped

**User story:** As a platform operator, I want recurring maintenance and confirmations summarised once
a day instead of ticketed one by one, while anything that needs a decision becomes a ticket.

1. THE Agent SHALL assign exactly one Disposition to every Consolidated_Event.
2. Default rules: `SERVICE_DISRUPTION`, `BREAKING_CHANGE`, `SECURITY_RELATED`, `COST_IMPLICATION`, and
   `UNCLASSIFIED` → `TICKET`; `INFORMATIONAL` → `DIGEST`.
3. THE deployment configuration SHALL allow overriding the Disposition per `eventTypeCode` (for
   example forcing a maintenance-class code to `DIGEST` regardless of class, or a code to `TICKET`),
   without code changes. The shipped default list SHALL mark known maintenance-class and confirmation
   codes as `DIGEST`.
4. WHEN a `DIGEST` event has an associated Precheck (R7) and the Precheck fails, THE Agent SHALL change
   the Disposition to `TICKET` naming the failing resources.
5. THE Agent SHALL send a digest at a configurable cadence (default daily) listing every `DIGEST` event
   since the previous digest with class, upcoming windows, affected accounts, and precheck results; an
   event SHALL appear in exactly one digest unless it changes.
6. THE Agent SHALL write an audit record for every Disposition decision so that no event is ever
   silently dropped.

### R7. Verify maintenance-class notices via investigation, escalate on evidence

**User story:** As a platform operator, I want the agent to check whether an AWS maintenance notice
actually threatens my workload, and only then raise a ticket, without maintaining per-check code whose
data source may never be provisioned.

**(Rewritten 2026-09-28, working spec `feat-devops-agent-enrichment`.) The pluggable, code-implemented
Precheck (previously R7.1) is retired.** The two shipped prechecks it described — EKS Fargate OS-patch
eviction risk and Amazon MSK security-patching risk — were, in the deployed system, always
`not_checked`: their optional read paths (a Kubernetes cluster access entry; `kafka:DescribeClusterV2`
+ CloudWatch) were never provisioned. Rather than maintain dead code pending a read path that may never
arrive, the checks themselves move to a DevOps Agent investigation, described to the investigating
agent rather than implemented as a Lambda function per `eventTypeCode`.

1. THE checks a maintenance-class notice needs SHALL be described in the DevOps Agent Incident RCA
   skill as things the investigating agent checks or explicitly reports it cannot see, including at
   least: for EKS Fargate OS-patch eviction risk, standalone pods without a controller, Deployments or
   StatefulSets with a single replica, PodDisruptionBudgets that block eviction (minAvailable 100% or
   maxUnavailable 0), and pods with more than one PDB; for Amazon MSK security patching, the
   `OfflinePartitionsCount` maximum during the previous patch window correlated with any open
   replication-factor-equals-min-ISR notice for the same cluster (skipping Express brokers, which do
   not carry this risk).
2. WHEN the investigation's `## Affected resources` table (R8.2) reports a row with `status: at_risk`
   for a `DIGEST`-dispositioned maintenance-class event, THE Agent SHALL escalate the Disposition to
   `TICKET` naming the at-risk resources — the same escalation R6.4 already describes, now fed by the
   parsed investigation table instead of a precheck function's return value.
3. THE Agent SHOULD additionally subscribe to the `aws.eks` "EKS Fargate Pod Scheduled Termination"
   EventBridge event and open a `TICKET` for each, since it is AWS's explicit eviction-failure signal.
   **(Unchanged.)**
4. WHEN the investigation reports it cannot see the data a check needs, THE Agent SHALL keep the event
   in the digest with that reason visible — the same behaviour R7.4 previously described for a
   `not_checked` precheck result, now sourced from the investigation's own reported limitation.
5. THE per-`eventTypeCode` disposition override (previously binding a precheck function name) SHALL
   be re-read as "this code's investigation may escalate on `at_risk` evidence," requiring no
   configuration migration.

### R8. Build a deterministic impact inventory for deadline-class events

**User story:** As an application owner, I want to know exactly which of my resources a deadline
applies to and whether I still need to act, before anyone spends time investigating.

1. FOR every `BREAKING_CHANGE`, `SECURITY_RELATED`, and `COST_IMPLICATION` event, THE Agent SHALL list
   affected resources per account from the event's affected entities with their AWS-reported status.
2. **(Rewritten 2026-09-28, working spec `feat-devops-agent-enrichment`.) Enrichment is a DevOps Agent
   investigation, not a per-service Lambda plug-in.** WHEN the affected account is covered by a
   registered Agent Space (R12.6), THE Agent SHALL request one investigation through the same gated
   webhook-and-callback mechanism R12 describes, tagged as an enrichment request, in place of the
   retired per-service lookups (previously R8.2: EKS, RDS/Aurora, Lambda). THE investigation's output
   SHALL be parsed against a fixed `## Affected resources` table contract (six columns: account,
   resource ARN, resource type, current version, status, evidence) by a deterministic parser before
   any downstream code treats it as data — the investigating agent's raw output is untrusted text
   (hard boundary #7) until it passes this contract. A malformed or missing table SHALL degrade to the
   entity-list baseline (R8.3) with the defect named, never to a silent partial inventory.
3. **(Corrected 2026-09-28, same working spec — R8.3 correction, `in_scope_unverified` added to the
   glossary.)** Impact_Status derivation SHALL treat the event's own affected-entity list as primary
   evidence, qualified by the event type's impact locus, in this order:
   - Entities present, impact locus `listed_resource`, no enrichment yet → `confirmed` (entity presence
     is itself confirmation; the investigation adds resource-state detail, it does not establish
     impact).
   - Entities present, impact locus `dependent`, no enrichment, or enrichment that did not verify the
     dependents → **`in_scope_unverified`**: these resources are subject to the event, but whether this
     account actually breaks depends on something AWS cannot see (a client trust store, a caller's SDK
     or TLS version). Never `confirmed` on entity presence alone for this locus.
   - Impact locus `dependent`, and the investigation verified the dependents (e.g. checked callers'
     trust stores or SDK versions via topology) → `confirmed` or `not_detected` **on that verified
     evidence** — the one case where an investigation can move the status rather than only add depth.
   - No entities, enrichment ran and found nothing → `not_detected`.
   - No entities and no enrichment ran (no covered account, or the account is not associated with the
     Agent Space that matched it) → `unverifiable`, with the specific reason named — `unverifiable`
     SHALL always include service-specific or client-side verification steps.
4. THE inventory SHALL be broken down by Environment_Type so that production impact is visible first.
5. WHEN all affected entities of a Consolidated_Event are reported resolved by AWS, THE Agent SHALL
   mark the event resolved and close its ticket (R11).

### R9. Project cost with a precision tool

1. FOR `COST_IMPLICATION` events and for `BREAKING_CHANGE` events that carry extended-support or
   pricing changes, a precision tool SHALL compute projected cost per affected account and an
   organization-wide total from the inventory (R8) and pricing inputs.
2. Pricing inputs SHALL come from configuration or the AWS Price List API, never from constants in
   code.
3. IF a projection cannot be computed, THEN THE tool SHALL return `unknown` with the reason.
4. THE Agent SHALL persist projections so that later reports can compare periods.

### R10. Route every ticket to an owning team

**User story:** As a platform operator, I want each ticket to reach the team that owns the affected
resources, with a sensible fallback, and to change the mapping without redeploying.

1. THE Agent SHALL resolve the owning team from a Routing table with precedence: resource tag on
   affected entities → affected account or its OU → AWS service → default team.
2. THE Routing table SHALL be deployment-time configuration (seeded at deploy, editable at runtime)
   holding team name, channel identifiers (SNS topic, Jira project, chat channel), and escalation
   contact.
3. WHEN no rule matches, THE Agent SHALL route to the default team and record `routing: default` on
   the ticket.
4. THE Routing table format SHALL be documented so that customers can generate it from their CMDB.

### R11. Maintain ticket and notification lifecycle by event ARN

**User story:** As an on-call engineer, I want one ticket per event that is updated as the event
evolves and closed when AWS closes it, not a new ticket on every update.

1. THE Agent SHALL publish a notification to the configured SNS topic for every `TICKET` disposition
   and every material update, using a stable, versioned JSON payload containing: event ARN, event type
   code, category, service, Regions, Classification and reason, Urgency, Deadline, Impact_Status with
   evidence or verification steps, cost projection, affected accounts with Environment_Type, affected
   resources with status, owning team, links to the AWS Health Dashboard, and any investigation result.
2. WHEN a ticket adapter is enabled, THE Agent SHALL create exactly one ticket per `eventArn`, update
   it in place on every new `lastUpdatedTime` (status change, added accounts or entities, entity
   resolution, urgency change, investigation result), and close it when AWS closes the event or all
   entities are resolved.
3. THE Agent SHALL store the mapping `eventArn → ticket identifier` so that updates survive restarts.
4. IF a sink call fails, THEN THE Agent SHALL retry with backoff, then record the failure on the
   Consolidated_Event and raise a metric; the event SHALL remain visible in the next digest.

### R12. Optional: verify impact with AWS DevOps Agent under gates and budgets

**User story:** As a platform operator, I want a topology-aware answer to "does this event affect my
workloads?" for live issues and hard deadlines, without duplicating investigations my monitoring tools
already trigger and without an open-ended bill.

1. THE module SHALL be disabled unless an Agent Space registry is configured; when disabled, tickets
   SHALL carry `impact: unverifiable` with verification steps exactly as in R8.
2. **Incident gate.** THE Agent SHALL request an investigation only for `issue` events with
   `statusCode = open` and, per the target Agent Space policy: for `ACCOUNT_SPECIFIC` events one
   investigation per event scoped to the affected accounts; for `PUBLIC` events one investigation per
   event scoped to accounts with resources in `eventRegion`; and for `accountNotification` codes on a
   configurable allow-list (e.g. EKS cluster health issues, VPN redundancy loss). Closed events SHALL
   never be investigated.
3. **Readiness, folded into the enrichment investigation (rewritten 2026-09-28, working spec
   `feat-devops-agent-enrichment`).** The readiness question — "is this forced change safe to make
   before its deadline, and what blocks it?" — is no longer a *second* investigation. THE Agent SHALL
   ask it of the **same** enrichment investigation R8.2 already requests for a deadline-class event,
   via the skill, answered in a `## Readiness` section using the existing feasibility / blockers /
   risk / rollback-available contract. Eligibility SHALL be decided per account: the class is
   `BREAKING_CHANGE` with a forced change or `SECURITY_RELATED` with a deadline, the Deadline is
   within a configurable horizon (default 90 days), and no assessment exists for that (event,
   account) — the same rule as before, minus the R8-confirmed-impact precondition, which is dropped
   because impact is now *discovered by* the investigation rather than known before it starts.
   Status-only updates SHALL NOT trigger a new assessment; a grown affected set SHALL re-run the
   investigation scoped to the new accounts only. **One investigation per deadline-class event, not
   two.** The durable per-(event, account) tracking this gate depends on for the grown-set
   set-difference is retained unchanged (see the design note this correction records, to prevent it
   being mistaken for something the readiness *module* needed and therefore also deletable — it is the
   webhook that is retired, not the tracking).
4. **Per-Agent-Space policy.** THE registry entry for each Agent Space SHALL define which categories,
   event codes, and scopes may trigger investigations, whether readiness assessments are enabled, and
   the monthly caps. The documentation SHALL recommend, for customers whose monitoring tools already
   trigger DevOps Agent, restricting incident investigations to control-plane and side-channel codes
   (API issues, PrivateLink, SES, identity, connectivity) that symptom-based monitoring does not see.
5. **Duplicate check.** BEFORE triggering, THE Agent SHALL query the target Agent Space for active
   investigations overlapping in accounts, Region, and a configurable time window (default ±60 min).
   IF one exists, THEN THE Agent SHALL NOT trigger, SHALL link the ticket to it, and SHALL add the
   event as context to it where the DevOps Agent API allows.
6. **Routing across accounts.** THE Agent SHALL select the Agent Space from the registry with
   precedence: affected account + workload tag → affected account → OU → organization default. Each
   registry entry SHALL hold owner account, Region, space identifier, trigger method (signed webhook
   with the credential referenced from AWS Secrets Manager, or a cross-account role to call the DevOps
   Agent API), callback expectations, policy, and caps. Unmatched accounts with no default SHALL not be
   investigated and the ticket SHALL say so.
7. **Results.** THE Agent SHALL correlate completion events forwarded from each owner account (or poll
   the investigation journal through the cross-account role) to the originating event, fold the result
   into the ticket as `impact: confirmed | not_detected | unverifiable` with a link to the
   investigation, and update the ticket in place (R11).
8. **Budgets and idempotency.** THE Agent SHALL enforce **one** monthly cap per Agent Space, covering
   every investigation it triggers — incident and enrichment alike **(the separate readiness cap
   retired 2026-09-28, working spec `feat-devops-agent-enrichment`, R12.3 revision: readiness is now
   the same investigation, not a second one with its own budget)** — and SHALL never trigger more than
   one investigation per `eventArn` per Agent Space. **Clarified, same working spec:** when an event's
   affected accounts map to more than one Agent Space (a federated organization with per-business-unit
   spaces), "one investigation per `eventArn` per Agent Space" means exactly that — **one per distinct
   space the affected accounts resolve to**, by design; a single event can therefore trigger several
   investigations, one per space, each independently subject to that space's own cap and duplicate
   check. THE Agent SHALL emit metrics for triggered, skipped as duplicate, and skipped by cap.
9. Deployment guidance SHALL note that an Agent Space must be created in a DevOps Agent supported
   Region and investigates resources in every Region of its associated accounts, so one space per
   environment or OU is usually sufficient. **(Co-location guidance added 2026-09-28, working spec
   `feat-devops-agent-enrichment`.)** THE reference deployment SHALL recommend, and its CDK SHALL
   implement, every Agent Space in the operations tooling account (the account running the triage
   stack) rather than in an owner account elsewhere — this keeps investigation-completion events
   same-account, so the central event bus's own callback rule receives them directly with no
   forwarding StackSet needed. Customers who must keep an Agent Space in a different account for
   data-segregation or compliance reasons re-add a forwarding rule for that owner account themselves;
   the callback handling is unchanged either way.

### R13. Optional: propose remediation as pull requests, never execute at runtime

1. WHEN enabled, THE Agent SHALL hand a confirmed deadline-class impact and its readiness assessment to
   a pull-request-generating step (following the AWS lifecycle-upgrade sample pattern) that opens a PR
   in the customer's infrastructure repository for human review and merge.
2. THE Agent SHALL NOT call mutating AWS APIs on customer resources. Any tool code that could mutate
   SHALL ship without the corresponding IAM permission and SHALL be listed in `MUTATING_ACTIONS.md`
   with the README warning block required by the framework.
3. THE legacy runtime remediation path (human-approved `eks:UpdateClusterVersion`) is retired in favour
   of the PR-based path.

### R14. Persist history and support reporting

1. THE Agent SHALL persist every Consolidated_Event, its classification history, dispositions, tickets,
   investigations, and cost projections with a configurable retention (default 400 days), because AWS
   Health retains events for 90 days. **(Substrate added 2026-09-28, working spec
   `feat-devops-agent-enrichment`.)** THE Intake Lambda SHALL additionally write the full consolidated
   event — every page, every entity, the full description — to a dedicated, KMS-encrypted, versioned
   S3 bucket keyed by event ARN, on every create or update, with the same 400-day retention enforced
   by the bucket's own lifecycle policy. This snapshot is both this requirement's persisted-history
   substrate and the mechanism by which an enrichment investigation (R8.2) reads the full event beyond
   what a generic webhook's `title`/`description` fields carry — the investigation webhook payload
   carries the S3 key, and the Agent Space's role is granted `s3:GetObject` on that prefix only.
2. THE Agent SHALL expose the persisted data so that period-over-period reports (events by class,
   digest ratio, tickets per team, investigations and cost) can be produced by precision tools.

### R15. Configuration, prompts, and models

1. All environment-dependent values (model ID and Region, table and topic names, thresholds, cadences,
   lists, registry and routing table locations) SHALL be read through one configuration module from
   environment variables, SSM Parameter Store, or the configuration tables; no other module SHALL read
   the environment directly.
2. THE system prompt SHALL live in `src/prompts/` and MAY be overridden from Amazon S3 at start-up; the
   source used SHALL be logged.
3. THE Amazon Bedrock model ID SHALL be configurable, defaulting to the approved model in the
   framework's technology standard with the cross-Region inference profile appropriate to the
   deployment Region.

### R16. Security and guardrails

1. THE Amazon Bedrock model SHALL be invoked with Bedrock Guardrails configured (content filters,
   denied topics, PII handling) as the framework requires. **Denied-topic evaluation SHALL use the
   `STANDARD` topic tier, not `CLASSIC`** — live testing showed `CLASSIC` false-positives on ordinary
   AWS Health notification text describing an AWS-initiated action (e.g. an end-of-support
   auto-upgrade notice) as autonomous-remediation intent, at rates from 40% to 100% depending on event
   type, while `STANDARD` resolved this to near-zero without weakening detection of real
   remediation-bypass attempts (verified 10/10 blocked on two real injection cases). `STANDARD`
   requires cross-Region guardrail inference; see design §3.3.
2. THE agent execution role SHALL be read-only against customer resources and scoped write-only to its
   own tables, queues, topics, and logs, with resource ARNs and the `agent-managed` tag condition.
3. All secrets (webhook credentials, Jira or chat tokens) SHALL be stored in AWS Secrets Manager and
   referenced by ARN; none SHALL appear in code, configuration tables, or logs.
4. Event descriptions are untrusted input (R4.5); tool outputs are data, not instructions.
5. Logs SHALL be structured JSON keyed by `eventArn` and SHALL NOT contain full model prompts or
   responses.
6. Data at rest SHALL be encrypted (KMS with rotation for tables, topics, queues, buckets); data in
   transit over TLS 1.2 or later.

### R17. Observability

1. THE Agent SHALL emit metrics for: messages received, de-duplicated, Consolidated_Events created and
   updated, classifications by class, dispositions by type, prechecks by result, tickets created,
   updated and closed, sink failures, investigations triggered, skipped-duplicate, skipped-cap,
   completed by outcome, and processing latency from EventBridge delivery to first notification.
2. THE deployment SHALL create alarms for error rate above 5%, dead-letter queue depth above zero, and
   p95 latency above the targets in Section 8.
3. AWS X-Ray tracing SHALL be enabled on all compute, and every log line SHALL carry the `eventArn`.

### R18. Naming and terminology

1. User-facing text SHALL say "AWS Health" or "AWS Health Dashboard"; "PHD" and "Personal Health
   Dashboard" SHALL NOT appear in code identifiers, resource names, documentation, or prompts.
2. Service names SHALL follow AWS naming standards on first mention (e.g. Amazon Bedrock, Amazon
   Bedrock AgentCore, Amazon Keyspaces for the `CASSANDRA` service code in user-facing text).

## 8. Non-functional requirements

| Area | Requirement |
|---|---|
| Latency | `issue` events: first notification within 5 minutes (p95) of EventBridge delivery. Other events: within 60 minutes (p95). Digest: at the configured time daily. |
| Scale | Designed for tens to hundreds of accounts and up to a few thousand messages per month with linear cost; no component holds state in memory across invocations. |
| Reliability | At-least-once delivery with idempotency; retries with backoff; dead-letter queue; zero silent drops. |
| Cost envelope | Language-model calls only for classification and verification-step drafting (once per Consolidated_Event and per material update). DevOps Agent spend bounded by per-space caps. |
| Portability | Any AWS Organizations customer in Regions where Amazon Bedrock and (optionally) AWS DevOps Agent are available; single CDK deployment plus one StackSet for per-Region rules and, optionally, per-owner-account roles. |
| Maintainability | Suppression lists, prechecks, routing, registry, thresholds, and prompts change without code changes. |

## 9. Hard boundaries

1. The agent never mutates customer resources at runtime. Remediation is a pull request a human merges.
2. No event is dropped silently: every event has a disposition and an audit record.
3. Exactly one classification and one disposition per event; one ticket per event ARN.
4. The language model never counts, calculates, compares dates, or projects cost; precision tools do.
5. The language model never triggers an investigation; deterministic gates do, within caps.
6. Closed events are never investigated.
7. Event text never changes agent behaviour.
8. No customer-identifying data (names, account IDs, ARNs, event text) in the repository, specs, or
   published eval report.
9. The agent complements the AWS Health Dashboard and AWS User Notifications; it does not replace them.

**Note (added 2026-09-28, working spec `feat-devops-agent-enrichment`):** boundaries #4 (the language
model never counts, calculates, or projects cost) and #5 (deterministic gates trigger investigations,
never the language model itself) hold on the DevOps Agent side of the enrichment path too, restated
there as explicit standing instructions in the `INCIDENT_TRIAGE` `AGENTS.md` — defence in depth
alongside the code-side gate, not a substitute for it. The investigating agent *lists* resources; code
counts and prices them.

## 10. Success criteria

Measured on the eval set (Section 11) and on the first deployment's own metrics.

| Criterion | Target |
|---|---|
| Classification accuracy on labelled synthetic events | ≥ 95% class agreement; 100% agreement on the priority rule when two classes apply |
| Deadline extraction | 100% when the description states a date; 0 false deadlines on events without one |
| Urgency computation | 100% (deterministic) |
| De-duplication | 100%: N messages for one event ARN yield one Consolidated_Event and one ticket |
| Digest ratio in a typical organization | ≥ 40% of distinct events dispositioned `DIGEST`, with 0 silent drops |
| Contract parse correctness **(replaces "precheck correctness," 2026-09-28, working spec `feat-devops-agent-enrichment` — prechecks are retired, R7)** | 100% on the deterministic eval cases: a well-formed `## Affected resources` table parses exactly; a malformed one degrades to the entity-list baseline with the defect named, never a silent partial inventory |
| Investigation gating | 100% of gate decisions match the policy on fixtures; duplicate check prevents a second trigger within the window; caps are never exceeded |
| Ticket lifecycle | For an event with k updates: exactly 1 create, k in-place updates, 1 close |
| Latency | Section 8 targets met on the first deployment's metrics |
| Operator acceptance (first deployment) | Operators report the digest as sufficient for maintenance notices and no missed actionable event over the pilot period |

## 11. Evaluation and hand-off

### Eval approach

Per the framework's eval standard, evaluation runs with EvalKit (Strands Evals SDK) at the end of
Build and reports per requirement. Deterministic components (R2, R5, R6 rules, R7, R8 lookups, R9,
R10, R11 lifecycle, R12 gates) are covered by unit and property-based tests with fixtures; the
language-model behaviour (R4 classification and reasons, R8 verification steps) is covered by EvalKit
scenarios with `toolcallingaccuracy` in focus to confirm that urgency, cost, and counts come from
precision tools.

### Eval data

A synthetic, labelled set built from the public AWS Health `eventTypeCode` values and description
wording published in AWS documentation, covering every family in Section 6, including the
disambiguation cases in R4.3, multi-page and multi-account events, status transitions (open → closed,
entity pending → resolved), and adversarial descriptions containing embedded instructions. No customer
data.

### Hand-off criteria

- **Ideation → Build:** this document, `design.md`, and `tasks.md` approved by the user; a Taskei ticket
  linked in `tasks.md`.
- **Build → Release:** all deterministic tests green; `eval/eval-report.md` present with the
  per-requirement table; master spec updated to match what was built; legacy specs archived; no
  customer data in the repository; `MUTATING_ACTIONS.md` present if any mutating tool code exists.

## 12. Assumptions to confirm at review

1. The agent is deployed in the AWS Health delegated administrator account (recommended) rather than
   the management account.
2. Amazon SNS is the core sink; Jira and chat are optional adapters in v1.
3. Digest cadence default is daily.
4. Kubernetes-API access for the EKS Fargate precheck is optional; without it the notice stays in the
   digest as `not_checked`.
5. The DevOps Agent module and the remediation module are off by default in the public sample and
   enabled by the first deployment.
6. The solution name `aws-health-event-triage-agent` replaces the legacy `phd_notification_classifier`
   package name.
