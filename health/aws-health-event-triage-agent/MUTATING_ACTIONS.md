# ⚠️ Mutating Actions — Disabled by Default

This agent is **read-only by default** for customer AWS resources. The agent's IAM
role (`infra/lib/core-stack.ts`, `infra/lib/triage-workflow.ts`,
`infra/lib/devops-agent-stack.ts`) only grants read-only actions against customer
accounts, plus read/write scoped to the agent's own DynamoDB tables, Secrets Manager
secrets, and log groups. See `iam-permission-boundary` steering for the full policy.

## Why This Is Disabled by Default

The aws-health-event-triage-agent inspects, humans change. It cannot accidentally
modify your environment even if the AI reasoning (the classifier, or a future
remediation step) produces an incorrect action plan.

## Currently Shipped Mutating Actions

**None.** No tool in this codebase currently calls a mutating AWS API against a
customer resource. Every `src/inventory/`, `src/cost/`, `src/intake/` function is
read-only (`describe*`, `list*`, `get*`) or a pure precision calculation.

## Planned: Phase 6 — PR-based remediation

Per the master spec (`.kiro/specs/aws-health-event-triage-agent/requirements.md`,
R13), Phase 6 will add a PR-generation step that proposes infrastructure changes as
a pull request for human review and merge — it explicitly does **not** execute any
mutating AWS API call at runtime. When Phase 6 ships, this file will be updated to
reflect whatever it actually builds, following Rule 2 of `iam-permission-boundary`:
mutating tool code (if any is ever built) is excluded from the default IAM role,
and this file documents exactly what additional permissions a customer would need to
grant, and why, before enabling it.

## If You Add a Mutating Tool

Before adding any tool that calls a mutating AWS API:

1. Build the tool code, but do **not** add the corresponding IAM permission to the
   default execution role in `infra/lib/*.ts`.
2. Document the required permission and its blast radius in this file, following the
   table format used elsewhere in this framework's `iam-permission-boundary` steering.
3. Add a README "⚠️ Optional: Enable Write Actions" section pointing here.
4. Get security review sign-off before shipping, per `security-policies` steering.
