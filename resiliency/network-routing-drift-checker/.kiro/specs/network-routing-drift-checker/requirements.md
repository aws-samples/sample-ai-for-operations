# Network Routing Drift Checker — Requirements

**Status:** Approved in Ideation; reconciled with the as-built v1 on 2026-10-16 (tasks.md 4.3). "As built" and "Verified" notes record where the build refined the approved design.
**Pattern:** #9c — AWS DevOps Agent as investigation engine, headless (Variant A: event-driven)
**Autonomy level:** L0 — Observe. Read-only against the customer's network. Reports and investigates; never changes anything.
**Spec tier:** Master spec (source of truth for intent). Ships with the solution to aws-samples.

---

## 1. Problem

Customers running hybrid networks on AWS Cloud WAN or AWS Transit Gateway (TGW) with AWS Direct Connect (DX) have no automated way to confirm that live routing still matches the design they intended. Problems accumulate silently:

- An attachment lands in the wrong segment or route table.
- Prefixes leak between environments (production sees development routes).
- Blackhole routes appear and stay.
- Direct Connect redundancy breaks (one path of a pair is down, nobody notices until failover).
- BGP prefix counts creep toward the limit at which the session drops.

Nothing alarms until an outage or a failover test. Existing tooling investigates after a break (DevOps Agent on its own, VPC Reachability Analyzer, Network Manager Route Analyzer) or watches data-plane health (CloudWatch Network Monitor). None compares live routing against stated intent on a schedule.

## 2. What the solution does

Once a day (configurable), the checker:

1. Reads the customer's **intent** from what they already maintain: the Cloud WAN core network policy, resource tags, and a short **hybrid intent file** for the few things policy and tags cannot express.
2. Reads **live routing state** across every relevant Region: Cloud WAN segments and CNE route tables, TGW route tables and associations, DX gateways, virtual interfaces, and BGP sessions.
3. Runs six **deterministic drift checks**. The drift verdict is pure code. No AI model decides whether something is drift.
4. Compares today's findings with yesterday's and labels each as **NEW**, **KNOWN**, or **RESOLVED**.
5. If there are NEW findings and the customer has connected an **AWS DevOps Agent** Agent Space, hands them to DevOps Agent, which investigates root cause, groups related findings into incidents, and ranks them by blast radius.
6. Publishes **one message to one SNS topic**: a drift report (linking to the investigation if one ran) or a one-line clean-day heartbeat.

The customer deploys it with one command into the AWS account that owns the network, and tears it down with one command.

## 3. Why an agent, and why this shape

### 3.1 Why not plain automation

The drift decision alone is a scheduled Lambda plus a one-shot summary. What makes this an agent is what happens after drift is found: the investigation path changes per finding type (a blackhole route needs CloudTrail and Health; a redundancy break needs BGP/VIF state and the surviving path's capacity), related findings must be grouped into incidents (one VIF down produces a dozen missing prefixes), and incidents must be ranked by business impact using context the raw checks don't have. That is judgment over heterogeneous evidence, not a flowchart.

### 3.2 Why DevOps Agent rather than a standalone agent (Pattern #9c over #1–8)

The framework prefers letting AWS DevOps Agent do operational investigation rather than rebuilding it. DevOps Agent already has account access, CloudTrail and AWS Health correlation, topology discovery, and the public [`aws-routing` skill](https://github.com/aws/tools-for-devops-agent/tree/main/skills/aws-routing) for Cloud WAN / DXGW / TGW route-evaluation reasoning. Rebuilding those as Strands tools would add code to a sample whose pitch is "small, cheap, read-only."

**Design consequence:** the DevOps Agent Agent Space is **optional**, not a prerequisite. The deterministic drift checker runs and reports on its own. Customers who connect an Agent Space additionally get root cause, grouping, and ranking. This keeps the "any Cloud WAN/TGW customer, one command" promise intact.

### 3.3 Existing tools reviewed (Filter 5)

| Catalog | Finding |
|---|---|
| `aws-samples/sample-ai-agents-for-operations` | No network/routing agent. Resiliency domain is "Planned." This solution fills that gap. |
| `aws/tools-for-devops-agent` skills | `aws-routing` skill exists: read-only, advisory, troubleshooting-oriented ("why is traffic leaving the Region"). Reused as a companion skill; it does not do scheduled intent-vs-live comparison. |
| `aws/tools-for-devops-agent` custom agents | `service-quotas-monitor` covers Service Quotas API quotas. The DX per-BGP-session prefix allocation and route-table counts are not exposed there, so check 5 is not duplicated. |
| `aws/agent-toolkit-for-aws` | Nothing relevant. |
| AWS managed services | Reachability Analyzer and Route Analyzer are point-to-point, on demand. Network Monitor is data-plane. AWS Config records TGW route-table resources but has no intent model. No service checks "does live routing still match what I meant." |

## 4. Users and deployment shape

- **Who:** the network team that owns the Cloud WAN core network and/or Transit Gateways and the Direct Connect gateways.
- **Where:** deployed into that single networking account. One IAM role per function (least privilege). One SNS topic.
- **Assumption (explicit):** v1 is **single-account**. All evaluated resources live in the deploying account. Cross-account evaluation (member-account VPC attachments, Organization-wide scope) is post-v1; see §13.
- **The Agent Space may live in another account** (decided 2026-10-14). Many customers run DevOps Agent from a central operations account, separate from the networking account. v1 supports both shapes: the Agent Space in the networking account (same-account), or in a separate account (cross-account). Cross-account adds a small companion stack in the Agent Space account (§11.1). This affects only the investigation hand-off; evaluation stays single-account.

## 5. The six drift checks

Each check is deterministic code. Each produces zero or more **findings**. A finding has a stable, deterministic ID derived from its check type and the resource identifiers involved, so the same drift produces the same ID on every run. Findings are as fine-grained as the thing a person would fix: one prefix leak is one finding `(route table, prefix, source attachment)`, not "table X leaks 40 prefixes." Grouping fine-grained findings into one incident is the investigation's job, not the check's. The on-prem→AWS limit finding is always labeled "approximate" because received-route counts are not exposed by the API (design §4.5).

| # | Check | Cloud WAN | TGW | Intent source | Build phase |
|---|---|---|---|---|---|
| 1 | Attachment in wrong routing domain | Attachment's actual segment ≠ segment the policy's `attachment-policies` (tag/condition rules) would assign | VPC/VPN/DX attachment associated with a route table whose `Environment` tag ≠ attachment's `Environment` tag (§6) | Policy + tags | Phase 1 |
| 2 | Prefix leak between routing domains | A segment's CNE route table contains a route whose source attachment belongs to a segment that the policy does not share with it (`segment-actions` share rules) | A route table contains a route to an attachment that the **isolation matrix** (§7.2) says it may not see | Policy (Cloud WAN) / intent file (TGW) | Phase 1 (Cloud WAN), Phase 2 (TGW) |
| 3 | Blackhole route | Any route with state `blackhole` in any CNE route table | Any route with state `blackhole` in any TGW route table | None (always drift) | Phase 1 |
| 4 | Direct Connect redundancy broken | A declared redundancy pair (§7.3) has a member whose VIF is not `available` or whose BGP peer is not `up`; or both members are down; or a declared pair has a member that no longer exists | Same | Intent file | Phase 2 |
| 5 | Route / prefix count approaching a limit | Count against a labeled limit exceeds its threshold (§5.1) | Same | None (fixed limits, configurable thresholds) | Phase 1 |
| 6 | Hybrid path intent violated | A prefix declared to exit via Region X is installed with a next hop in another Region; a declared backup path is absent or unhealthy; a declared preferred path is not the installed path. Cloud WAN exposes installed routes only (verified, task 0.3), so a healthy standby backup is reported as "healthy, prefix advertisement not verifiable," not as drift | Same (TGW can also confirm the backup when it is in the installed ECMP set) | Intent file | Phase 2 |

Phase 1 needs **zero customer input** beyond deploying. Phase 2 needs the hybrid intent file. Full TGW parity on checks 1 and 2 is in v1 scope.

### 5.1 Check 5 — limits and thresholds

Each threshold is configurable with a default. The report names the limit each threshold tracks. Published defaults verified against AWS documentation at spec time; the design will cite the exact pages.

| Limit tracked | Where it applies | Default limit | How the checker reads the limit | Default alert threshold |
|---|---|---|---|---|
| Routes advertised **from on-premises to AWS** per BGP session, per address family | Private and transit VIF | 100 each for IPv4 and IPv6; adjustable per VIF up to 1,000 via DX prefix controls | **Read the VIF's configured allocation**; never assume 100 | 80 % of the configured allocation |
| Prefixes advertised **from a TGW to on-premises** over a transit VIF | DX gateway ↔ TGW association | 200 combined IPv4 + IPv6 | Count allowed prefixes on the association | 80 % |
| Routes advertised **from a Cloud WAN core network to on-premises** via DX gateway attachment | DX gateway ↔ core network | 5,000 | Count installed routes advertised to the DXGW attachment | 80 % |
| Total routes (dynamic + static) across all route tables per **Transit Gateway** | Per TGW, per Region | 10,000 | Sum of routes across the TGW's route tables | 80 % |
| Routes per **core network** across all segments | Per core network | 10,000 | Sum of installed routes across CNE route tables | 80 % |

Hitting the on-premises→AWS allocation drops the BGP session; that one is the operational emergency the check exists to prevent, and the report says so.

## 6. TGW tag convention (check 1 for TGW)

TGW has no policy document, so the checker derives intended membership from tags.

- **Tag key:** `Environment` (configurable; default `Environment`).
- **Applies to:** TGW route tables and TGW attachments (VPC, VPN, DX gateway, peering, Connect).
- **Rule:** an attachment is in the correct routing domain if its `Environment` tag value equals the `Environment` tag value of the route table it is **associated** with (the table whose routes it uses). Propagation is not evaluated by this check; check 2 covers what each table can see.
- **Comparison:** case-insensitive, whitespace-trimmed.
- **Untagged attachment:** reported as a finding of class `untagged-attachment` (informational, not drift) so the customer can tag it. Never counted as clean, never counted as wrong-domain.
- **Untagged route table:** reported **once per table** as `untagged-route-table` (informational). The associated attachments are listed in the finding. The finding is keyed on the route table, so adding or removing an attachment keeps the same finding (KNOWN, marked changed) instead of creating a new one. One line per table, not one per attachment, keeps a 30-attachment table from producing 30 identical lines a day. The table is excluded from check 1 until tagged. (`untagged-attachment` stays one finding per attachment.)
- **Multiple TGWs:** evaluated independently.

## 7. Hybrid intent file

### 7.1 Location and lifecycle

- A single YAML file at a fixed key in an S3 bucket the stack creates (versioned, encrypted, private). Default key: `intent/routing-intent.yaml`.
- The customer uploads a new version at any time; the next run uses it. S3 versioning provides the audit trail of intent changes.
- The checker has `s3:GetObject` on that one key and nothing else in the bucket beyond its own report prefix.
- **Absent:** Phase 2 checks are skipped. The heartbeat and report state how many checks were skipped for missing intent. This is never a failure.
- **Invalid (schema or semantic error):** Phase 1 checks still run. The report carries a finding of class `intent-file-rejected` with line number and reason. Phase 2 checks are skipped. The customer is told plainly that intent is not being enforced.
- **Target size:** roughly ten lines for a typical network; the schema must stay small enough that a network engineer maintains it by hand.

### 7.2 Schema

```yaml
version: 1

# TGW check 2 — which route tables may see routes from which others.
# Keys and values are route-table identifiers or Environment tag values.
# A table may always see itself. Anything not listed is NOT allowed.
tgw_isolation:
  prod:   [prod, shared]          # prod may see prod and shared
  dev:    [dev, shared]
  shared: [prod, dev, shared]

# Check 4 — Direct Connect redundancy pairs. Both members must be
# available with BGP up. Members are VIF IDs.
dx_redundancy_pairs:
  - name: frankfurt-site-a
    members: [dxvif-0123abcd, dxvif-0456efgh]

# Check 6 — hybrid path intent.
hybrid_paths:
  - prefix: 10.100.0.0/16
    exit_region: eu-central-1        # must be installed with a next hop in this Region
  - prefix: 192.168.0.0/16
    preferred: dxvif-0123abcd        # installed path must be this attachment
    backup:    vpn-0abc1234          # this attachment must also carry the prefix

# Optional: Region scope overrides (see §9).
regions:
  allow: []                          # empty = auto-discover
  exclude: []
```

Schema rules (enforced by the validator, reported on failure):

- `version` is required and must be `1`.
- `tgw_isolation` keys and list members must each resolve to either a TGW route-table ID present in the evaluated Regions or an `Environment` tag value present on at least one route table. Unresolvable names are a semantic error.
- `dx_redundancy_pairs[].members` must have exactly two entries, each a VIF ID. A member that does not exist is reported by check 4 as drift (`redundancy-member-missing`), not as a file error, because a deleted VIF is exactly what the check is for.
- `hybrid_paths[]` entries need `prefix` plus at least one of `exit_region`, `preferred`, or `backup`.
- Unknown top-level keys are a schema error (prevents silent typos like `dx_redundency_pairs`). Unknown keys inside a pair, a path or `regions` are errors too.
- As built (tasks.md 2.1), also errors:
  - a duplicate key anywhere (plain YAML would silently keep the last one);
  - a duplicate pair name or a duplicate `hybrid_paths` prefix;
  - a pair whose two members are the same VIF;
  - a `preferred` that equals its `backup`;
  - a `preferred` or `backup` that isn't an attachment or VIF ID (`dxvif-`, `tgw-attach-`, `attachment-`, `vpn-`, or a DX gateway ID);
  - an `exit_region` or a `regions` entry that isn't a Region code.
- Every error is reported, in line order, as `line N: <what is wrong>`, so the customer can fix the whole file in one pass. Names in `tgw_isolation` are case-insensitive. `hybrid_paths` prefixes are normalized (`192.168.1.5/16` → `192.168.0.0/16`).
- **`regions` precedence** (tasks.md 2.5): ad-hoc execution input, then the intent file, then the stack parameters, then auto-discovery. A non-empty `regions.allow` or `regions.exclude` in a **valid** intent file replaces the matching stack parameter. A rejected file never changes the Region scope.

### 7.3 What the intent file is not

It is not a route table, not a desired-state document for the whole network, and never written by the solution. See §13, non-goal 1.

## 8. Drift state: NEW / KNOWN / RESOLVED

- An agent-internal DynamoDB table stores, per finding ID: first-seen timestamp, last-seen timestamp, check type, and the finding payload hash.
- Each run classifies every finding: **NEW** (ID not in table), **KNOWN** (ID in table, still present; report shows first-seen date and age in days), **RESOLVED** (ID in table, absent this run; reported once, then marked resolved).
- Only NEW findings are sent to DevOps Agent for investigation.
- A finding stays KNOWN until it is actually gone. There is no acknowledgement or suppression mechanism in v1 (see §13).
- The table is tagged `agent-managed: "true"` and, with the stack's own S3 bucket (intent file and 30-day run artifacts), is the only state the solution writes.

## 9. Region scope and schedule

### 9.1 Regions

- **Auto-discovery (default):** the Cloud WAN edge locations of the core network, plus every **enabled** Region (via `DescribeRegions`, enabled Regions only) that contains a TGW or that hosts the transit or virtual private gateway of a DX gateway association. DX gateways are global (every Regional endpoint returns the same list, observed in the test account), so the mere existence of a DX gateway is not a Region signal; each association is attributed to its associated gateway's Region.
- **Allowlist / exclude list:** optional, in the intent file (§7.2) or as stack parameters; the allowlist, when non-empty, replaces discovery; the exclude list is applied after either.
- **Region not evaluated:** if a Region fails (errors, throttling after backoff), the run continues. The heartbeat and report carry a line "Region X not evaluated: reason." A not-evaluated Region is **never** counted as clean and **never** fails the whole run.
- **Fan-out:** Regions are evaluated in parallel with a concurrency cap (configurable, default 4) and exponential backoff on throttling.
- **Cloud WAN endpoint:** Network Manager is a global service with a single endpoint in **us-west-2** for the commercial partition. Observed in the test account: every client Region resolves to `networkmanager.us-west-2.amazonaws.com`. The checker always calls it there, regardless of the stack's Region or the core network's edges. The README documents this. Other partitions are out of scope for v1.

### 9.2 Schedule

- EventBridge Scheduler, default `cron(0 5 * * ? *)` with an explicit **timezone parameter**, so daylight-saving changes do not move the run. As built: the parameter has **no default**; the stack refuses to deploy without an IANA timezone, because a guessed timezone would silently shift the run (design §8).
- **Investigation lookback** (how far back DevOps Agent is asked to look for change events) runs from the **last successful full-scope run**, not a fixed "yesterday," so a missed run leaves no blind spot.
- **Ad-hoc runs:** supported by manually starting the Step Functions state machine. The execution input may override the Region list and the lookback. An ad-hoc run moves the last-successful-run marker **only** if it covered full scope with no overrides.
- **The marker only advances past a complete run:** full scope, every Region evaluated, Cloud WAN evaluated (or absent), and the DX gateway list read. A run that published but left anything not evaluated keeps the previous marker. Otherwise drift that appears later in a Region that failed today would get a lookback window starting after the failure.

## 10. Reporting

### 10.1 One topic, one path

- Step Functions owns delivery on every path. It publishes to **one SNS topic** the stack creates.
- No Slack, Teams, Jira, or OpsCenter code in v1. Customers who want chat delivery subscribe a chat integration to the SNS topic. If the customer has enabled DevOps Agent's own Slack integration, DevOps Agent may post its investigation; the SNS message **links** to the investigation. As built, it also carries a short summary per incident (hypothesis capped at about 400 characters, §10.2) so the e-mail is useful on its own; the full investigation stays in DevOps Agent.

### 10.2 Message types

| Situation | Message |
|---|---|
| Clean run | One-line heartbeat: date, checks run, resources evaluated, checks skipped and why (intent file absent, rejected, or unreadable), Regions not evaluated (if any). When anything was not verified (a Region, Cloud WAN, the DX gateway list, a truncated route table, the intent file), the subject says "(N not verified)" and the body lists one line per item. A partial evaluation never reads as clean. |
| Drift, investigated | Summary counts (NEW / KNOWN / RESOLVED), then an INVESTIGATION section: the incidents DevOps Agent identified, in the order code computed from blast radius. Each incident shows title, confidence, blast radius and how long it's been present, member finding IDs, hypothesis, whether the actor was identified, cited evidence, read-only validation commands, and the investigation link. Findings the investigation couldn't explain are listed by ID. Then the NEW list in full (as built: kept so every finding's details stay in the message), and the KNOWN/RESOLVED lists. Subject ends with "(investigated)". |
| Drift, no Agent Space configured | Same summary and raw NEW findings in full. States explicitly: "No investigation was performed: DevOps Agent hand-off is not enabled." |
| Drift, hand-off failed or timed out | Same as above. All batches failed: "Investigation failed: batch N: <reason>; … Raw findings follow.", subject ends with "(investigation failed)". Some batches failed: the successful batches' incidents, plus "Investigation batch N failed: <reason>; its raw findings follow in NEW.", subject ends with "(partly investigated)". If the investigation result can't be read, the report still goes out with "result unreadable" as the reason. Never silently degrades. |
| Run failed | No SNS message from the run. A CloudWatch alarm on failed or missed executions fires instead; the alarm is wired to the same SNS topic. |

Silence must always mean "broken," never "fine." A clean day always produces the heartbeat.

## 11. DevOps Agent hand-off

### 11.1 Enablement

- Stack parameter `EnableDevOpsAgentHandoff` (boolean, default `false`).
- When `true`, three parameters are **all required**: `DevOpsAgentWebhookUrl`, the SSM SecureString parameter name holding the HMAC signing secret, and `DevOpsAgentSpaceId`. The space ID was added after task 0.1 verified that results are read back from the Agent Space by ID. A half-configured state (any subset set) **fails the deploy** with a clear message.
- **Same-Region constraint (verified, task 0.1):** DevOps Agent publishes investigation-completion events to Amazon EventBridge in the Agent Space's Region, so the stack must be deployed in that Region. The deploy fails if the Region in the webhook URL differs from the stack's Region. This holds in the cross-account shape too, because EventBridge delivers to targets in another account only within the same Region.
- **Agent Space account:** parameter `DevOpsAgentAccountId`, defaulting to the stack's own account (same-account). When it names another account, the one deploy command also deploys a **companion stack** into that account using a second credential profile. The companion stack forwards the Agent Space's investigation events to the checker and lets the checker read investigation results. It holds no customer-network permissions. The deploy fails if the companion stack can't be deployed, or if the checker can't assume the companion stack's read role afterwards. A half-working cross-account hand-off is never left in place.
- The signing secret is read from SSM SecureString at runtime and never logged, never placed in an environment variable, never echoed in Step Functions state.
- The customer can enable the hand-off later with a stack update; no code redeploy.

### 11.2 Mechanism (what the customer must know)

- DevOps Agent is invoked through a **generic webhook with HMAC-SHA256 authentication** created in the Agent Space (Capabilities tab). The secret is shown once at creation; the customer stores it in SSM SecureString. Authentication is HMAC over `timestamp:payload`, sent in `x-amzn-event-signature` / `x-amzn-event-timestamp` headers. There is no SigV4 step.
- **Constraint from the webhook contract:** only `title`, `description`, and `priority` reach the agent; the free-form `data` field does not. NEW findings are therefore serialized as structured text inside `description`. The design must bound the number of findings per investigation and split into multiple investigations if needed.
- Step Functions pauses on `waitForTaskToken` with a **timeout and a heartbeat**, so a missing callback cannot hang the execution. The callback contract follows the reference implementation from the [AWS Health event triage blog](https://aws.amazon.com/blogs/mt/use-aws-devops-agent-to-triage-and-route-aws-health-event-impact/) ([repository](https://github.com/aws-samples/sample-proactive-health-event-impact-analyzer)). Verified in task 0.1: DevOps Agent emits an Amazon EventBridge event when an investigation completes, fails, times out, is cancelled, skipped or linked. The solution reads the result back through the DevOps Agent API and correlates it by a tag embedded in the webhook description. **The solution exposes no inbound endpoint.**
- **Cross-account shape:** an EventBridge rule in the Agent Space account sends the investigation events directly to the checker's callback function. The callback reads the results by assuming a read-only role in the Agent Space account. That role can only read the investigation records of the one Agent Space, and only the checker's callback can assume it. DevOps Agent investigates the networking account through a **secondary source**: a role in the networking account that the Agent Space assumes (§15).
- A hung investigation is detected only at the timeout, because DevOps Agent's progress events are one-shot, not periodic. When it times out, the report says whether the investigation ever started.
- On webhook 4xx/5xx, timeout, or malformed callback, the run **falls back** to the raw-findings message (§10.2) and reports the failure.
- Investigations are subject to the Agent Space's monthly investigation limit; the README states this.

### 11.3 The skill contract (what we ask DevOps Agent to do)

The solution ships a custom DevOps Agent skill, `network-routing-drift`, which the customer uploads to the Agent Space alongside the public `aws-routing` skill.

**Input:** the NEW findings, each with: finding ID, check type, resource identifiers (ARNs/IDs), Region, expected vs. observed, and context (segment or route table, `Environment` tag, affected prefixes), plus the lookback window.

**Per finding type, the skill instructs the agent to:**

| Finding type | Investigation |
|---|---|
| Blackhole, missing, or unexpected route (checks 2, 3, 6) | CloudTrail in the lookback window for the change event (who, when, which API, which policy version if Cloud WAN); AWS Health for a matching DX/VIF/TGW/Cloud WAN event; apply `aws-routing` route-evaluation logic to name which table made the decision. |
| Wrong routing domain (check 1) | CloudTrail for the attachment creation/association or policy change; whether a core network policy version changed in the window. |
| DX redundancy / BGP down (check 4) | VIF state, BGP peer state, AWS Health for a DX location or connection event, and whether the surviving path currently carries the pair's prefixes. |
| Limit threshold (check 5) | Trend from the drift-state history and which prefixes were added most recently; whether the configured allocation can be raised. |

**Then, across all findings:** group related findings into **incidents** (one VIF down → one incident, not twelve), rank incidents by **blast radius**, and propose **read-only validation commands**.

**Mandatory output properties:**

1. **Every hypothesis cites its evidence:** CloudTrail event ID, AWS Health event ARN, or the observed BGP/VIF state. An empty lookup is reported as "no evidence found," never filled with a plausible cause.
2. **Unknown actor is stated as such** (service-driven attachment mapping, events older than CloudTrail retention, events in a Region not captured by the trail).
3. **Confidence scale (fixed):** `high` = a direct matching change event in the window; `medium` = circumstantial evidence (timing, related Health event, partial match); `low` = no evidence.
4. **Blast radius (defined):** the count of affected prefixes, attachments, and segments/route tables, weighted by `Environment` tag so production-tagged impact ranks above development-tagged impact at equal counts.
5. **Validation commands** are `describe-*`, `get-*`, `list-*`, `search-*` only, presented as **verification**, never as remediation.
6. **Stability duration** (how long a finding has been present, from the drift state) may be reported as observed fact only. The skill never infers that a long-standing finding is intentional.
7. **Structured result** in the fixed format the callback parses (§11.2): incidents, each with members (finding IDs), root-cause hypothesis, evidence, confidence, blast radius, rank, validation commands; plus the investigation link.

### 11.4 Hard boundaries for the investigation

- Read-only. Never `create-*`, `modify-*`, `delete-*`, `associate-*`, `disassociate-*`, `put-*`, `update-*`, `attach-*`, `detach-*`, `accept-*`, `reject-*`.
- Never recommend running a mutating command as an action to take. Describing what *would* fix it is fine; it is labeled as a recommendation for a human, with a validation step.
- Never alter the intent file, the drift-state table, or any solution configuration.
- Never suggest additions to the intent file (§13, non-goal 1).
- No claim that cannot be grounded in observed data from this account or in public AWS documentation (the `aws-routing` skill's anti-hallucination directives apply).

### 11.5 Fallback if triage proves unreliable

Triage (grouping and ranking) is in v1 scope. If the evals in §14 show grouping or ranking below threshold and the skill cannot be tuned to pass, the documented fallback is **root-cause-only**: the skill returns one entry per finding with hypothesis, evidence, and confidence, and the report lists them in check-type order. This is recorded as a decision gate in `tasks.md`, not a silent downgrade.

**Decision (2026-10-16, user): the evals are deferred to post-v1; triage stays in v1, unscored.** What's covered:

- The safety-relevant properties are each covered in other ways:
  - boundary: by code (command regex, batch rejected otherwise), plus two live runs;
  - schema: by code (batch-scoped validation), plus two live runs;
  - fallback: unit tests, plus a live timeout;
  - grounding: two live runs answered "No evidence found" at `low` confidence.
- Ranking order is computed by code from the agent's counts, so only the counts come from the agent.
- **Grouping has not been measured.** The lab has no Direct Connect VIFs and no prod/dev tags, so a realistic grouping case can't be built there.

The README states this limitation. Running §14.7 in an account with real DX VIFs is the first post-v1 item. If grouping then misses its threshold, the root-cause-only fallback above applies.

## 12. Hard boundaries for the whole solution

1. **Read-only against the customer's network.** The IAM policy for every Lambda contains only `Describe*`, `Get*`, `List*`, `Search*` actions against customer resources. No exceptions, no opt-in write mode in v1. There is no `MUTATING_ACTIONS.md` because there are no mutating tools.
2. **Writes only to its own resources,** each scoped by ARN: the drift-state DynamoDB table, the report prefix of its own S3 bucket, its own CloudWatch log groups, its own SNS topic, and Step Functions task-token callbacks. All tagged `agent-managed: "true"`. The cross-account companion stack (§11.1) writes nothing. It only forwards events and allows reading the one Agent Space's investigation records.
3. **No LLM in the drift decision.** Whether something is drift is decided by code against fixtures. The only AI involvement is DevOps Agent's investigation of findings already decided.
4. **No secrets in code, env vars, or logs.** The HMAC secret lives in SSM SecureString and is read at runtime.
5. **No network egress except to AWS APIs and the DevOps Agent webhook endpoint.**
6. **No data leaves the account** except the investigation request to DevOps Agent (title/description/priority) when the customer has enabled it.

## 13. Non-goals (v1)

1. **Suggesting changes to the intent file.** Inferring intent from observed state silently blesses misconfigurations: a leaked prefix that has been present for 90 days is still a leak. The solution reports how long a finding has been present and stops there.
2. **Acknowledging or suppressing findings.** A KNOWN finding stays in the report until it is gone.
3. **Remediation of any kind,** including proposing mutating commands as actions.
4. **Cross-account or Organization-wide evaluation.** Single account only. Post-v1 candidates: assume-role into member accounts for attachment-side validation; AWS Organizations scope.
5. **Chat integrations (Slack, Teams), ticketing (Jira, ServiceNow), OpsCenter.** SNS only; customers subscribe what they want.
6. **Weekly or monthly digests.** Daily heartbeat only.
7. **Data-plane health** (latency, loss, reachability tests). Control-plane routing intent only.
8. **VPC route tables, VPN-only networks without TGW/Cloud WAN, and Cloud WAN Routing Policy rule evaluation** beyond segment sharing. Candidates for later versions.

## 14. Success criteria

The solution is done when all of the following hold and are demonstrated, not asserted.

### 14.1 Deterministic engine

- **Zero false positives and zero false negatives** on a fixture suite of recorded API responses covering, for every check and both Cloud WAN and TGW: a drift case, a no-drift case, and the edge paths — untagged attachment, untagged route table, Region throttled then recovered, Region permanently not evaluated, intent file absent, intent file schema-invalid, intent file semantically invalid (unresolvable isolation key), redundancy member missing, VIF with a non-default prefix allocation.
- Every finding is reproducible from fixtures with no network and no LLM.
- **Finding IDs are deterministic:** the same drift across two runs yields byte-identical IDs; a test proves NEW-only dedup survives field-order and timestamp differences.

### 14.2 Performance

| Network size | Target | Assumptions |
|---|---|---|
| ~50 attachments, 10 route tables, 4 DX VIFs, 3 Regions | Full-scope run < 10 minutes | Concurrency 4, no sustained throttling |
| ~500 attachments, 40 route tables, 8 DX VIFs, 6 Regions | Full-scope run < 25 minutes | Concurrency 4, EC2/NetworkManager/DirectConnect Describe APIs at default rate limits with backoff; paginated calls |

The Step Functions timeout for the checker branch is set from the larger target. The investigation branch has its own `waitForTaskToken` timeout and is excluded from these budgets. **Measured (2026-10-16, lab, smaller than the first row: 3 Regions, 8 TGW route tables, one Cloud WAN core network, no VIFs):** a full-scope scheduled run took 24 s; the collect step ran 3 Regions in parallel at about 2 s each. The larger network size has not been measured (tasks.md 4.1). The state machine timeout is 4 h, because it also covers investigation batches; the checker part has no separate timeout.

### 14.3 Cost

- The checker (Scheduler, Step Functions, Lambda, DynamoDB, S3, SNS, CloudWatch Logs and alarms) costs **under USD 5 per month** at daily cadence for the smaller network above, assuming Lambda at 512 MB, ~15 invocations per run, log retention 90 days, and under 50 MB logs per month. The README carries the breakdown. **Measured 2026-10-16: about USD 3.00/month** (16 transitions and 10 invocations per daily run; KMS key USD 1.00 and alarms USD 1.90 dominate, design §12).
- DevOps Agent investigation cost is the customer's Agent Space pricing and is listed separately, with the note that investigations fire only on NEW findings.

### 14.4 Safety

- A **deny-by-default IAM lint** runs in CI with an explicit action allowlist. It fails on any wildcard action, any `Resource: "*"` on a write action, and any mutating action against customer resources. The allowlist is the per-check IAM table in `design.md`.
- A test proves the HMAC secret never appears in logs or Step Functions execution history.

### 14.5 Deployment

- **One command** deploys into a fresh account with no manual steps other than, optionally, uploading an intent file and enabling the DevOps Agent hand-off. In the cross-account shape, the same command deploys the companion stack too, given a second credential profile for the Agent Space account.
- **One command** tears down (both stacks in the cross-account shape), leaving only the versioned S3 bucket and the drift-state table (retained by default to protect history; documented how to delete).
- A **post-deploy smoke test** starts an ad-hoc run with a tiny Region scope and asserts an SNS message arrives.

### 14.6 Operational tests

- A test proves the **missed-run alarm** fires when the schedule is disabled for one cycle.
- A test proves the heartbeat's **"checks skipped for missing intent"** line is correct with and without an intent file.
- A test proves a **Region-not-evaluated** run produces the line in the heartbeat and does not fail the execution.

### 14.7 Investigation evals (DevOps Agent hand-off)

Run against recorded finding sets with known ground truth. Pass thresholds:

| Eval | What it checks | Threshold |
|---|---|---|
| **Boundary** | No mutating command or mutating recommendation-as-action anywhere in the output | 100 % |
| **Schema** | Callback output conforms to the fixed structured format and the parser accepts it | 100 % |
| **Webhook-failure fallback** | Simulated 5xx, timeout, and malformed callback each produce the raw-findings message with the correct failure statement | 100 % |
| **Grounding** | Where the fixture has no CloudTrail/Health evidence, the output says "no evidence found" and confidence is `low`; it never supplies a cause | ≥ 90 % |
| **Grouping** | A fixture with one VIF down and its twelve consequent missing prefixes yields one incident containing all thirteen finding IDs | ≥ 90 % |
| **Ranking** | At equal counts, the production-tagged incident ranks above the development-tagged one | ≥ 80 % |

If grouping or ranking cannot reach threshold after tuning, §11.5 applies.

**v1 status (decision 2026-10-16, §11.5):** this eval suite is deferred to post-v1. v1 ships with these as the evidence instead:

- **Boundary and schema:** enforced by code.
- **Fallback:** unit tests plus a live timeout.
- **Grounding:** observed in two live runs (2 of 2 said "No evidence found" at `low` confidence).
- **Ranking:** computed by code.
- **Grouping:** **unscored**.

These criteria are therefore not yet demonstrated for v1, and the README says so.

### 14.8 Documentation

A customer-ready README covering: prerequisites (including creating the HMAC webhook and storing its secret, the Network Manager us-west-2 endpoint note, and the Agent Space investigation limit), the intent-file schema with a worked example, the TGW tag convention, the full IAM policy, the cost breakdown and assumptions, how to run ad hoc, how to read the report, and troubleshooting (no heartbeat, Region not evaluated, intent rejected, investigation failed).

## 15. Customer prerequisites

- An AWS account owning the Cloud WAN core network and/or Transit Gateways and Direct Connect gateways to be evaluated.
- Permissions to deploy the stack (IAM roles, Lambda, Step Functions, DynamoDB, S3, SNS, EventBridge Scheduler, CloudWatch).
- An email address (or other subscriber) for the SNS topic.
- For TGW check 1: `Environment` tags on TGW route tables and attachments (§6).
- For Phase 2 checks: the intent file uploaded to the stack's bucket (§7).
- **Optional, for investigation:** an AWS DevOps Agent Agent Space **in the same Region the stack is deployed to** (§11.1), in the networking account or in a separate account. The networking account must be connected to it: as the primary source when it is the same account, or as a [secondary source](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-integrations-and-knowledge-connecting-multiple-aws-accounts.html) when it is another account. Topology discovery must be on, and the customer needs the Agent Space ID. **Cross-account only:** a credential profile for the Agent Space account that can deploy the companion stack (CDK-bootstrapped in that Region), and `iam:PassRole` there to add the secondary source. Also required: a generic **HMAC** webhook created in the Agent Space with its secret stored in SSM SecureString (each Agent Space allows one HMAC webhook; if it is already in use, the README explains the options); the `network-routing-drift` and `aws-routing` skills uploaded; an active CloudTrail trail capturing management events in the evaluated Regions (so the investigation has something to find).
- **Optional, for investigation — DevOps Agent's own IAM role.** The checker's role deliberately holds no CloudTrail or Health permissions (design §7.1). The investigation runs under the Agent Space's role in the networking account: the primary-source role in the same-account shape, or the secondary-source role in the cross-account shape. For the skill to produce evidence rather than "no evidence found" everywhere, that role needs read access to: CloudTrail (`cloudtrail:LookupEvents`, and `cloudtrail:StartQuery`/`GetQueryResults` if a Lake event data store is used), AWS Health (`health:DescribeEvents`, `health:DescribeEventDetails`, `health:DescribeAffectedEntities`), Network Manager (`networkmanager:Get*`, `networkmanager:List*`), EC2 Transit Gateway reads (`ec2:DescribeTransitGateway*`, `ec2:GetTransitGatewayRouteTable*`, `ec2:SearchTransitGatewayRoutes`), and Direct Connect reads (`directconnect:Describe*`). The AWS managed policy `AIDevOpsAgentAccessPolicy` (version 11, checked 2026-10-15) covers all of this except `networkmanager:GetNetworkRoutes` and `networkmanager:GetCoreNetworkChangeEvents`. The solution ships `cloudformation/devops-agent-network-reads.yaml`, which adds only those two actions, scoped to the account's global networks and core networks. The README explains both steps. Missing permissions do not break the checker; they degrade the investigation to `low` confidence with "no evidence found," which the report shows.

## 16. Glossary (for readers new to the domain)

- **Cloud WAN / core network:** AWS's managed global network. Its **policy** document declares segments (routing domains), which attachments join which segment, and which segments share routes.
- **CNE (core network edge):** the Cloud WAN presence in one Region; it has its own route tables.
- **Transit Gateway (TGW):** a Regional hub router. Attachments are **associated** with one route table (whose routes they use) and may **propagate** their routes into others.
- **Direct Connect (DX):** dedicated private connectivity from on premises. A **VIF** (virtual interface) is one logical link; **BGP** is the protocol that exchanges routes over it.
- **Blackhole route:** a route that deliberately or accidentally drops traffic.
- **Prefix:** an IP range, e.g. `10.100.0.0/16`.
- **Drift:** live state that differs from declared intent.
