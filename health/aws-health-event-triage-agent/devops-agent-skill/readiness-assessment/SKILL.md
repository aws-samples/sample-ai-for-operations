---
name: health-event-readiness-assessment
description: Assesses whether a forced or deadline-bound AWS Health event
  change is safe to make. Determines feasibility, blockers, risk, and
  rollback availability. Use this skill when investigating a readiness
  assessment for an AWS Health event that carries a deadline (breaking
  changes, security-related changes with a required-by date) — not for
  active-incident investigations, which use the health-event-impact-assessment
  skill instead.
---

# Health Event Readiness Assessment

Use this skill when an investigation is triggered as a **readiness assessment**
for an AWS Health event — a forced or deadline-bound change (a breaking change
or a security-related change with a required-by date) where the question is not
"what is the blast radius of an active issue" but **"is this change safe to make,
and what stands in the way?"**

This is a different judgment from the incident-gate's impact assessment. Do not
confuse the two: an incident investigation asks about an event that is already
happening; a readiness assessment asks about a future, scheduled, or deadline-bound
change that has not happened yet.

This skill is generic across AWS Health event families (EC2, RDS, EKS, Lambda,
and others) — it reasons in terms of the AWS Health event fields already
available (service, event type, affected resources, deadline), not in terms of
any one service's specific upgrade mechanics.

## Step 1: Understand the Forced Change

From the incident data, extract:
- The AWS service and event type driving this change
- The deadline (the date by which the change must be made)
- The specific resources affected and, where available, their current
  configuration relevant to the change (e.g. current version, current
  instance type, current API usage)
- The accounts this assessment covers (an event may affect multiple accounts;
  the investigation prompt lists which accounts to assess for this run —
  some accounts may already have a separate assessment on file)

## Step 2: Assess Feasibility

Using the application topology and available account/resource data, determine
whether the change can be made safely before the deadline:

- **READY**: All prerequisites are satisfied. The change can proceed with no
  known obstacles.
- **BLOCKED**: A concrete condition prevents the change today (e.g. an
  incompatible dependency, a required upgrade that has not happened, missing
  quota, an unowned/unmonitored resource).
- **NEEDS_REMEDIATION**: The change is not blocked outright, but a specific
  action must be completed first (e.g. update a dependent library, migrate a
  workload off a deprecated feature) before it is safe to proceed.

If you cannot determine feasibility from available data (no topology match,
insufficient account access, or genuinely ambiguous information), say so
plainly in the analysis — do not guess. The callback that parses this output
treats a missing or unrecognized `FEASIBILITY` value as `unverifiable` rather
than assuming readiness, so it is always safer to describe what you don't know
than to force an answer.

## Step 3: Identify Blockers

For a `BLOCKED` or `NEEDS_REMEDIATION` outcome, list the specific, concrete
conditions preventing the change — not general risk commentary. Each blocker
should be something an operator could act on directly (e.g. "add-on version
X.Y is incompatible with target version Z", "instance type not available in
this account's AZ", "no rollback snapshot configured").

For a `READY` outcome, there are no blockers.

## Step 4: Assess Risk

Independent of feasibility, assess how risky making this change is:

- **LOW**: Well-tested change path, strong redundancy, low likelihood of
  customer impact even if something goes wrong.
- **MEDIUM**: Some risk — partial redundancy, some untested aspects, or
  moderate customer-facing exposure.
- **HIGH**: Significant risk — no redundancy, customer-facing, or a change
  path with known failure modes.

## Step 5: Assess Rollback Availability

Determine whether a rollback path exists if the change causes problems (a
prior version to revert to, a snapshot, a blue/green cutover that can be
reversed). Answer plainly YES or NO — if this is genuinely unknown, prefer NO
(the conservative assumption) and explain why in the analysis.

## Output Format

Your final response **must** include the fixed heading and key-value block
below, verbatim. The AWS Health Event Triage Agent's callback Lambda
(`src/devops_agent/callback_handler.py`, parsing logic in
`src/devops_agent/readiness_outcome.py`) pattern-matches on this exact
structure; free-form prose without this block will result in an
`unverifiable` outcome even if your analysis contains a clear answer.

```
## Readiness Assessment

FEASIBILITY: READY | BLOCKED | NEEDS_REMEDIATION
BLOCKERS: <comma-separated list, or NONE>
RISK: LOW | MEDIUM | HIGH
ROLLBACK_AVAILABLE: YES | NO

<freeform analysis explaining the assessment — what you checked, what you
found, and why you reached this conclusion. Reference the specific accounts,
resources, and deadline from the investigation prompt.>
```

### Heading and field rules

- Use `## Readiness Assessment` exactly. The callback parser searches for
  this heading first, then falls back to scanning the full response if the
  heading is missing — but always include it.
- `FEASIBILITY`, `RISK`, and `ROLLBACK_AVAILABLE` must use exactly one of the
  listed values (case-insensitive). Any other value is treated as
  unrecognized and degrades to `unverifiable`/`unknown`/unset respectively —
  never invent a new value or leave the line out.
- `BLOCKERS` must be a comma-separated list of short blocker descriptions, or
  the literal word `NONE` (case-insensitive) when there are no blockers.
- Put the four key-value lines together, in this order, immediately under the
  heading, before any freeform prose.

### Note on ticket tracking and remediation

This deployment already maintains its own ticket per AWS Health event ARN,
created and updated automatically outside this investigation. **Do not**
create, search, or comment on any external ticketing system (Jira or
otherwise), and **do not** open a pull request, propose a code change, or
take any remediation action as part of this investigation. This skill's job
ends at producing the structured readiness assessment above — generating
remediation (a PR, a config change, an upgrade plan) is a separate capability
this deployment does not yet include. Confine your output to the format
above.
