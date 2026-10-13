---
name: health-event-impact-assessment
description: Evaluates AWS Health event impact on application workloads using
  topology knowledge, enumerates affected resources with their current state,
  and assesses whether a forced or deadline-bound change is ready to make. Use
  this skill for incident root-cause analysis investigations triggered by AWS
  Health events including scheduled maintenance, operational issues, service
  degradation notifications, and deadline-class breaking changes (runtime/
  version deprecations, certificate rotations, extended support).
---

# Health Event Impact Assessment

Use this skill when an investigation is triggered by an AWS Health event. Your goal
is to (1) assess the impact on workloads in the topology, (2) for deadline-class
events, enumerate the specific affected resources with their current state, (3)
determine which teams need to be notified, and (4) when asked, assess whether the
change is ready to make.

**Retargeted 2026-09-28** (working spec `feat-devops-agent-enrichment`, task 10):
this skill's deployment now targets `INCIDENT_RCA` specifically (previously
`GENERIC`) via the deploy command's `--metadata '{"agent_types":["INCIDENT_RCA"]}'`
parameter — the narrowest applicable agent type, per this framework's own
guidance to reduce context consumption and improve focus. Agent-type targeting
is deploy-time metadata, not a `SKILL.md` frontmatter field (the frontmatter
schema is only `name`/`description`, confirmed against the framework's own
`devops-agent-skill` steering). This skill also now covers the resource-
enumeration and readiness roles that were previously split across per-service
Lambda plug-ins and a second, separate investigation — see `## Step 0` and
`## Step 6` below.

## Step 0: Read the Full Event

The investigation's `[HEALTH_TRIAGE:...]` tag in the incident description already
tells you the event's classification, urgency, deadline, affected accounts,
region, and impact locus — **do not re-derive or second-guess these values; they
were computed by code before this investigation started** (this repository's own
defence in depth, see `AGENTS-incident-triage.md`).

The description also carries an `[EVENT_SNAPSHOT:<s3-key>]` tag. **Before
enumerating resources, read the full consolidated event at that S3 key.** The
webhook's own title/description fields are truncated summaries; the S3 snapshot
carries every affected entity (across all pages), the full AWS-provided
description text, and status per entity — you need this to know exactly which
resources to enumerate in Step 4.

## Step 1: Identify Affected Resources

From the incident data (and the full event snapshot from Step 0), extract:
- The AWS service affected (EC2, RDS, Lambda, etc.)
- The region and availability zone
- The maintenance window or event timeline
- Specific resource IDs listed as affected

Cross-reference these with the application topology to find which applications
use the affected resources directly or transitively through dependency chains.

## Step 1a: Check the Impact Locus — Does the Investigation Target Flip?

The `[HEALTH_TRIAGE:...]` tag carries `impactLocus`, one of two values. **Read it
before deciding what to enumerate in Step 4** — it changes what "affected
resources" means for this event:

- **`impactLocus=listed_resource`** (the common case): the resources AWS listed
  in the event **are** the things that break, cost money, or get retired (a
  Lambda runtime deprecation, an RDS engine end-of-support, an EKS cluster
  version EOL). Enumerate those listed resources directly — their current
  state (version, configuration, health) is what Step 4's table needs.

- **`impactLocus=dependent`** (certificate/CA rotations, TLS version
  deprecations, deprecated-API removals): the resources AWS listed are **in
  scope**, but whether any given account is actually impacted depends on
  something AWS cannot see from the resource side — a client's trust store
  contents, its negotiated TLS version, or its SDK version. **For a `dependent`
  event, your investigation target flips: enumerate the CALLERS of the listed
  resources, not the resources themselves.** Use the topology to find which
  workloads connect to the listed tables/endpoints, then assess each caller's:
  - Trust store contents (does it already trust the new CA/certificate?)
  - Negotiated TLS version and minimum supported version
  - SDK/runtime version (does it default to the old or new behavior?)

  Only emit the `## Dependents verified: yes` line (Step 6) when you have
  actually assessed the callers' posture this way. **Re-listing the same
  tables/endpoints AWS already listed, without checking any caller, is NOT
  verification** — if you cannot determine a caller's trust store or TLS
  configuration from the topology, say so explicitly and emit
  `## Dependents verified: no` rather than guessing.

## Step 2: Assess Blast Radius

For each affected application in the topology:

1. **Direct impact**: Resources explicitly listed in the Health event
2. **Transitive impact**: Downstream services that depend on affected resources
   (e.g., an ALB routing to affected EC2 instances, an application reading from
   an affected RDS instance)
3. **Redundancy evaluation**: Check if the application has:
   - Multi-AZ deployment (resources in other AZs can absorb traffic)
   - Auto Scaling groups that can replace affected instances
   - Read replicas or failover configurations
   - Cross-region redundancy

## Step 3: Determine Impact Severity

Assign severity per affected workload:

- **CRITICAL**: Service will be unavailable, no redundancy, customer-facing
- **HIGH**: Significant degradation expected, partial redundancy insufficient
- **MEDIUM**: Some impact but redundancy mechanisms should handle it
- **LOW**: Minimal impact, full redundancy in place, automatic recovery expected

Overall investigation severity = highest individual workload severity.

## Step 4: Identify Responsible Teams

For each affected workload, determine the owning team by checking:
1. Resource tags (Team, Owner, Department, CostCenter)
2. CloudFormation stack ownership (stack tags, stack name patterns)
3. Application topology groupings and service boundaries

Build a notification routing list with:
- Team name/identifier
- Contact method (email, Slack channel, MS Teams channel)
- Severity of impact on their workload
- Specific resources they own that are affected

## Step 5: Generate Recommendations

For each affected workload, provide actionable recommendations:
- Pre-event mitigations (migrate instances, failover databases, scale out)
- During-event monitoring (what metrics to watch, what alarms to set)
- Post-event validation (health checks, data integrity verification)

Prioritize recommendations by:
1. Time sensitivity (maintenance window approaching)
2. Impact severity (CRITICAL workloads first)
3. Effort required (quick wins before complex changes)

## Step 6: Enumerate Affected Resources (deadline-class events only)

**Added 2026-09-28** (task 10) — this step replaces what per-service Lambda
plug-ins (`src/inventory/eks.py`, `rds.py`, `lambda_.py`) used to do in code. If
this investigation is for a deadline-class event (`[HEALTH_TRIAGE:...]` class is
`BREAKING_CHANGE`, `SECURITY_RELATED`, or `COST_IMPLICATION`), enumerate every
affected resource (or, for `impactLocus=dependent` events per Step 1a, every
affected caller) with its **current state**, so the ticket can show exactly what
needs to change:

- **resource_arn**: the full ARN of the resource (or caller) — never a bare
  name or ID. If you cannot determine a real ARN, use the closest identifying
  string you have, but prefer the topology's own ARN field when present.
- **resource_type**: a short type label (`rds-instance`, `eks-cluster`,
  `lambda-function`, `eks-deployment`, etc.).
- **current_version**: the resource's actual current version/configuration
  value most relevant to this event (engine version, Kubernetes version,
  Lambda runtime, or for a `dependent` event, the caller's negotiated TLS
  version / SDK version). Use `unknown` only if genuinely undiscoverable, not
  as a default.
- **status**: exactly one of `affected`, `at_risk`, `not_affected`,
  `inaccessible`, `unknown` (see below).
- **evidence**: a short, specific justification — cite the actual data point
  (e.g. "engine aurora-postgresql 11.9, EOL 2026-02-28", "2 Deployments with
  replicas=1 in namespace fp-default", "client SDK 1.2.0 defaults to trusting
  only the old root CA").

**Status meanings:**
- `affected`: the resource is in scope and will be impacted by the deadline as
  described (engine will actually reach EOL, runtime will actually be blocked).
- `at_risk`: the resource is in scope **and** your investigation found a
  specific configuration that will make the maintenance/change unsafe (see
  the checks below) — this status escalates a digest-bound notice to an
  immediate ticket, so only use it when you have concrete evidence.
- `not_affected`: in scope per the event, but your investigation found the
  resource is not actually susceptible (e.g. a caller already trusts the new
  CA for a `dependent` event).
- `inaccessible`: you could not investigate this specific account's
  resources because you do not have access to it (the account is not
  associated with this Agent Space). Name the account and the denied action
  in `evidence` (e.g. `AccessDenied: no association for 444455556666`) — do
  **not** guess at its state.
- `unknown`: you attempted to determine the state but genuinely could not
  (data unavailable, ambiguous topology) — explain why in `evidence`.

### Maintenance-safety checks (req E3.2)

For these specific event families, check the following before assigning
`at_risk` — these checks replace the deleted `fargate_posture` and
`msk_patch_safety` precheck functions:

- **EKS Fargate OS patching events** (`AWS_EKS_FARGATE_POD_EVICTIONS`): check
  each affected cluster's namespaces for standalone pods (no owning
  Deployment/ReplicaSet/StatefulSet), single-replica Deployments, and
  PodDisruptionBudgets whose `minAvailable`/`maxUnavailable` would block the
  patching rollout from evicting pods safely. Any of these found → `at_risk`,
  name the specific namespace/workload in `evidence`.
- **MSK security patching events** (`AWS_KAFKA_SECURITY_PATCHING_EVENT`): check
  the cluster's recent offline-partition history and whether any topic's
  replication factor is at the minimum in-sync-replica count (a broker
  restart during patching could then cause an availability gap). Either
  condition found → `at_risk`. Express brokers are exempt from this check
  (they use a different patching mechanism).
- **If you cannot determine these conditions from the topology** (no
  Kubernetes-level visibility, no Kafka cluster metrics available), report
  `status: unknown` for that resource with `evidence` naming exactly what data
  you could not see — this is the case the deleted prechecks' `not_checked`
  result used to represent, now sourced from your own investigation instead
  of an unimplemented data-read path.

## Step 7: Readiness Assessment (when asked)

**Added 2026-09-28** (task 10) — previously a separate investigation; now the
same investigation answers this question when the incident gate's decision
included it (`askReadiness` was true). Using the application topology and the
resources enumerated in Step 6, assess:

1. **FEASIBILITY**: `READY` (safe to make now), `BLOCKED` (something must
   change first), or `NEEDS_REMEDIATION` (fixable before the deadline with
   effort).
2. **BLOCKERS**: specifically what blocks it, if anything — name the exact
   condition (e.g. "cluster prod-eks-1 has 3 Deployments with replicas=1 and no
   PodDisruptionBudget headroom").
3. **RISK**: `LOW`, `MEDIUM`, or `HIGH` — how risky is making this change.
4. **ROLLBACK_AVAILABLE**: `YES` or `NO` — is a rollback path available if the
   change causes problems.

If the incident gate did not ask this question for this event, omit the
`## Readiness` section entirely (see Output Format below).

## Output Format

Your final response **must** use the markdown structure below verbatim.
The AWS Health Event Triage Agent's callback Lambda
(`src/devops_agent/callback_handler.py`, parsing logic in
`src/devops_agent/outcome.py`, `src/devops_agent/affected_resources.py`, and
`src/devops_agent/readiness_outcome.py`) pattern-matches on these specific
section headings; free-form prose without these headings will result in
empty findings.

```
## Summary

<one-paragraph executive summary, ≤ 500 chars>

## Key Findings

- **<workload-name>**: <impact severity> — <one-line impact statement>.
  Affected resources: <comma-separated IDs>. Redundancy: <yes/no/partial>.
- **<workload-name>**: ...
- **<workload-name>**: ...

## Answers to Your Questions

<freeform analysis, references the investigation prompts>

## Recommended Actions

| Priority | Action |
|----------|--------|
| **P1**   | <highest-priority action> |
| **P2**   | <next action> |
| **P3**   | <next action> |

## Notification Routing

For each owning team:
- **<team-id>**: <severity> impact on <workloads>. Contact via <channel>.

## Affected resources

| account | resource_arn | resource_type | current_version | status | evidence |
|---|---|---|---|---|---|
| <12-digit-account-id> | <full-arn> | <type-label> | <version-or-config> | <status> | <specific-justification> |

## Dependents verified: yes

## Readiness Assessment

FEASIBILITY: READY
BLOCKERS: NONE
RISK: LOW
ROLLBACK_AVAILABLE: YES
```

### Heading rules

- Use `## Summary`, `## Key Findings`, `## Answers to Your Questions`,
  `## Recommended Actions`, and `## Notification Routing` exactly. The
  callback parser pattern-matches on these.
- Each finding bullet must follow the `- **<title>**: <detail>` shape.
  The parser extracts the bolded title and the detail after the colon.
- Recommendations must be in a markdown table whose first column is
  `**P1**` / `**P2**` / `**P3**` (or higher). The parser maps these
  priority labels onto this agent's `impact`/severity levels.
- If there is genuinely no impact, still emit the `## Summary` section
  with one paragraph explaining why, and skip the rest. Do not fabricate
  empty sections — the parser interprets emptiness correctly.

### `## Affected resources` — mandatory for deadline-class events (req E2, task 10)

- **Only include this section for deadline-class events** (`BREAKING_CHANGE`,
  `SECURITY_RELATED`, `COST_IMPLICATION` per the `[HEALTH_TRIAGE:...]` tag) —
  omit it entirely for `issue`/`accountNotification` investigations that don't
  need resource-level enumeration.
- **The header row's six column names, in this exact order, are the parse
  anchor** — `account | resource_arn | resource_type | current_version |
  status | evidence`. A different order, a missing column, or a renamed
  column causes the ENTIRE table to be rejected and the ticket falls back to
  AWS's own entity list, losing your enumeration's depth. Copy the header
  row verbatim from the template above; do not paraphrase it.
- `account` must be the real 12-digit AWS account ID. `resource_arn` must
  start with `arn:`. A row failing either check is dropped individually
  (the rest of your table still counts) — but if every row fails, the whole
  table is treated as if it were never emitted.
- `status` must be exactly one of `affected`, `at_risk`, `not_affected`,
  `inaccessible`, `unknown` (see Step 6 above for their meanings). Any other
  word is normalized to `unknown` with a warning — it does not fail the row,
  but it does lose the specific meaning you intended.

### `## Dependents verified: yes` — only for `impactLocus=dependent` events (req §1a, task 10)

- **Omit this line entirely for `impactLocus=listed_resource` events** — it
  is ignored if present, but including it only for `dependent` events keeps
  your output unambiguous.
- For a `dependent` event, write `## Dependents verified: yes` **only when
  you actually assessed the callers' trust store / TLS / SDK posture** per
  Step 1a. Write `## Dependents verified: no` (or omit the line) when you
  could not — including when you only re-listed the same tables/endpoints
  AWS already listed without checking any caller. **This line is the ONLY
  thing that can move a `dependent` event's status past "in scope, impact
  unverified" — get it right rather than defaulting to "yes."**

### `## Readiness Assessment` — only when the investigation was asked to assess readiness (task 10)

- **Omit this entire section if you were not asked a readiness question**
  (no readiness-related prompt text in the investigation description). Do
  not fabricate a readiness assessment for an investigation that didn't
  request one.
- When present, use exactly the four `KEY: VALUE` lines shown in the
  template, in that order, with the exact enumerated values from Step 7.
  `BLOCKERS` is a comma-separated list, or the literal word `NONE`.

### What "no impact" looks like

When the affected resources do not appear in any workload topology, or
they are fully redundant such that the event causes no service disruption,
emit:

```
## Summary

<one paragraph explaining no operational impact, why redundancy
absorbs the event, and that no action is required>
```

…and stop. Do not include `## Key Findings` or `## Recommended Actions`
sections. The callback will mark the investigation outcome as
`not_detected` based on the absence of findings/recommendations and the
keywords "no operational impact" / "no immediate operational" /
"no workloads".

### Note on ticket tracking

This deployment already maintains its own ticket per AWS Health event ARN
(created and updated automatically outside this investigation, via the AWS
Health Event Triage Agent's own routing and sink dispatch). **Do not**
create, search, or comment on any external ticketing system (Jira or
otherwise) as part of this investigation — doing so would create a
duplicate ticket alongside the one this agent already manages. Confine
your output to the headings above; ticket creation and routing are handled
outside this skill.
