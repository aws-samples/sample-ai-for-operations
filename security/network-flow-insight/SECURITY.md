# Security

This document is the threat model, data classification and control list for network-flow-insight. Report
vulnerabilities through the process in the repository root's security policy, not in public issues.

**Verification.** Written on 28 October 2026 from a STRIDE analysis, then checked against the code in this folder
(`infra/lib/agent-stack.ts`, `src/network_flow_insight/`, `Dockerfile`, `requirements.txt`). Every control below is
cited to a file and line. Where the code does less than the design says, the threat is marked
**Open** and the gap is stated.

## What the agent does and does not touch

| | Customer estate | Agent-managed |
|---|---|---|
| Reads | Amazon VPC Flow Logs in one Amazon S3 bucket, the AWS Glue table, Amazon EC2 and AWS Config inventory, Amazon CloudWatch gateway metrics, the AWS Price List; in local runs only, optional AWS Cost and Usage Report and Amazon Route 53 Resolver-log tables, through a read-only role the operator supplies | its own aggregate and reports |
| Writes | **Nothing.** No code path calls a mutating API on a resource the agent did not create. | report bucket, a Glue database and tables for aggregates, an Amazon Athena workgroup |

The execution role has no customer-environment write action (`infra/lib/agent-stack.ts:224-292`). Its write
statements are limited to the agent's own report bucket, KMS key and Glue database (`:295-305`). They are scoped by
ARN; there is no tag condition. `tests/unit/test_e13_e14_boundaries.py` checks the synthesized template. Because
there are no mutating customer actions, no `MUTATING_ACTIONS.md` is needed.

Creating the agent's own Glue database and workgroup is agent-internal. Locally it happens only with
`--create-resources` or `nfi create-table --confirm` (`src/network_flow_insight/aws_backend.py`, `cli.py`). In the
hosted form the stack creates them, and the runtime role has no `glue:CreateDatabase` or `athena:CreateWorkGroup`.

## Data classification

Flow-log records are network metadata: private and public IP addresses, ports, byte counts, and interface, account
and Region identifiers. They contain no payload. Treat them as **internal**. Reports hold aggregates, named
resources and classified destinations. They never contain raw flow records. The aggregate keeps source and
destination addresses at full precision, so treat the report bucket as internal data too.

Chat mode can return raw flow-log rows at the user's request (up to 60 per query shown to the model,
`src/network_flow_insight/toolset.py:41`). They are not written to reports.

Tool results go to the model, including internal addresses, ports and resource names. See threat T12.

## Risk summary

Counts use the residual severity after the controls below. There are no HIGH threats.

| STRIDE category | High | Medium | Low | Total |
|---|---|---|---|---|
| Spoofing | 0 | 0 | 2 | 2 |
| Tampering | 0 | 0 | 7 | 7 |
| Repudiation | 0 | 0 | 1 | 1 |
| Information Disclosure | 0 | 0 | 3 | 3 |
| Denial of Service | 0 | 1 | 2 | 3 |
| Elevation of Privilege | 0 | 0 | 2 | 2 |
| **Total** | **0** | **1** | **17** | **18** |

By status: 7 mitigated, 10 accepted, 1 open. **Unmitigated HIGH threats: 0 (gate: pass).**

## Detailed findings

Component paths are relative to this folder. "Open" means the control is incomplete and a change is recommended.

### Spoofing

- **T7 [Low, mitigated] Forged `ip-ranges.json`.** Component: `src/network_flow_insight/core/ipranges.py`.
  `https://` is required (`:104-105`) and the certificate is verified with the botocore CA bundle (`:88-95`, `:110`).
  A pinned local or S3 copy is supported through `ip_ranges_file` (`src/network_flow_insight/config.py:63`).
- **T8 [Low, mitigated] Another account's service assumes the runtime role.** Component: `infra/lib/agent-stack.ts`.
  The trust policy names the Amazon Bedrock AgentCore service and carries `aws:SourceAccount` and `aws:SourceArn` conditions
  (`:212-216`).

### Tampering

- **T3 [Low, accepted] Instruction-like text in a tag, resource name or Resolver name steers the model.**
  Components: `src/network_flow_insight/agent.py`, `src/network_flow_insight/toolset.py`. Controls: the system prompt
  says tool results are data (`src/network_flow_insight/prompts/system_prompt.md:73-78`); the Amazon Bedrock Guardrail has a
  prompt-attack input filter (`infra/lib/agent-stack.ts:165`); no tool takes a destination path
  (`src/network_flow_insight/toolset.py:326-328`); report narrative with a figure absent from the findings is dropped
  (`src/network_flow_insight/tools/render_report.py:51`) and chat figures that no tool returned get a caution
  (`src/network_flow_insight/agent.py:141`, `:164`). The wording of an answer is not checked. In one guardrail-off test
  the model flagged a planted instruction as untrusted data and did not act on it; that is a single run. Every tool is
  read-only against the estate, so the worst outcome is a misleading answer or extra Athena spend inside the budget.
- **T4 [Low, mitigated] SQL that writes, drops, reads another table or calls a deny-listed function.**
  Component: `src/network_flow_insight/core/sqlsafe.py`: one SELECT (`:91-94`), table allowlist (`:111`), deny list and
  `$path` (`:129-132`), LIMIT capped (`:141-148`). Rejected statements are never executed
  (`src/network_flow_insight/tools/run_athena.py:19-21`). SQL built by the tools uses validated identifiers, quoted
  values and dates re-parsed as plain `YYYY-MM-DD` at the point of use
  (`src/network_flow_insight/core/tablescheme.py:24`, `:80-83`, `:86-101`, `:104-105`). The role has no write on the
  flow-log bucket (`infra/lib/agent-stack.ts:224-227`).
- **T5 [Low, mitigated] A caller chooses where a file or object is written.** `render_report` takes only a narrative.
  The destination is the configured reports directory plus a stamp from the validated window
  (`src/network_flow_insight/toolset.py:326-328`, `:103-104`). Hosted, the directory is a fresh temporary one and the
  S3 prefix is built from the validated mode and ISO dates (`src/network_flow_insight/agentcore_app.py:50`, `:73`).
- **T6 [Low, accepted] Markup, a formula or a link in a report.** HTML and SVG are escaped
  (`src/network_flow_insight/tools/render_report.py:847`, `:930`) and Markdown table cells escape the pipe
  (`:829`). CSV fields (`:881`, `:890`) and Markdown text outside tables are not neutralised. This matters only if a
  reader opens a CSV in a spreadsheet and a resource name starts with `=`, `+`, `-` or `@`.
- **T9 [Low, accepted] The agent starts without a Guardrail.** `src/network_flow_insight/agent.py:41-46` refuses to
  start without one unless `NFI_ALLOW_NO_GUARDRAIL=true`, a development override that is logged
  (`guardrail_disabled`). The hosted stack always sets `GUARDRAIL_ID` (`infra/lib/agent-stack.ts:379-380`). Changing
  the runtime environment is a privileged action.
- **T10 [Low, accepted] A reused aggregate is altered.** Components: report bucket, agent Glue database. Changing it
  needs write access to agent-managed resources (`infra/lib/agent-stack.ts:298-305`); the bucket is versioned
  (`:117`). `find_aggregate` checks only the table's creation time (`src/network_flow_insight/tools/build_aggregate.py:27-58`),
  not an integrity value.
- **T17 [Low, accepted] Altered code in the container or code zip.** Python versions are pinned in
  `requirements.txt` and installed as binary wheels (`infra/build_runtime_zip.py:53-55`). The CDK dependencies are
  pinned to exact versions in `infra/package.json` with a lockfile (`infra/package-lock.json`). The container runs as
  a non-root user (`Dockerfile:21-22`). There is no hash pinning and no vulnerability scan in the product. Add both in
  your pipeline.

### Repudiation

- **T15 [Low, accepted] The product's own logs cannot name the session or tool for a query.** Each Athena query is
  logged with its execution ID, scanned bytes, elapsed time and row count
  (`src/network_flow_insight/core/athena.py:127-131`) and the report lists the queries it ran
  (`src/network_flow_insight/tools/render_report.py:915`). No log line records a session ID or a tool name. Athena's
  query history and AWS CloudTrail give attribution at a coarser level. Add per-tool logging if you need attribution
  inside the product.

### Information Disclosure

- **T11 [Low, accepted] Reports are read by someone who should not.** The report bucket blocks public access,
  requires TLS, is versioned and access-logged, and has default encryption with a rotating customer-managed key
  (`infra/lib/agent-stack.ts:96`, `:113-118`). Report objects carry no per-object encryption header, so that key
  applies to them (`src/network_flow_insight/tools/write_report.py:39-45`); a reader needs object access and key
  access. Athena query results use the workgroup's KMS setting (`:144-147`). The local reports directory relies on
  the operator's file permissions.
- **T12 [Low, accepted] Tool results reach the model service.** Internal addresses, ports and resource names are part
  of the prompt; that is how the agent works. The path uses TLS and IAM. The default model ID is a cross-Region
  inference profile (`src/network_flow_insight/config.py:27`) and the role may invoke the profile and its foundation
  model in any Region (`infra/lib/agent-stack.ts:307-312`). Choose a profile that meets your residency rules.
- **T13 [Low, mitigated] AWS credentials appear in a log, a result or the model.** No secret fields exist in
  `src/network_flow_insight/config.py`; credentials come from the standard chain or the runtime role. The Guardrail
  blocks AWS keys and passwords (`infra/lib/agent-stack.ts:195-197`). Log lines carry error classes, execution IDs
  and counts, or the first 200 characters of an error string (`src/network_flow_insight/tools/write_report.py:48-50`,
  `src/network_flow_insight/tools/list_log_prefixes.py:23-25`). There is no redaction filter; credentials stay out by
  construction.

### Denial of Service

- **T1 [Low, mitigated] One query scans far more than the gauge estimated.** The cost estimate for a raw-table
  query covers the requested window (`src/network_flow_insight/tools/query_raw.py:33`). The SQL gate admits a
  raw-table statement only if its `WHERE` holds, as top-level `AND` terms, a literal start and end date for the day
  column that both lie inside that window (`src/network_flow_insight/core/sqlsafe.py:113-117`, `:222-259`; applied by
  `query_raw.py:27-32`). `day > '2000-01-01'`, `day = day`, an `OR`, a `NOT`, a one-sided range and a range outside
  the window are rejected and never run. The per-session budget still counts actual scanned bytes after each query
  (`src/network_flow_insight/core/athena.py:223-226`).
- **T14 [Medium, open] Repeated hosted chat sessions.** In hosted chat a query above the ceiling is skipped
  (`src/network_flow_insight/core/athena.py:289-296`) and the prompt is cut at 8000 characters
  (`src/network_flow_insight/agentcore_app.py:42`). Athena itself stops any one query that scans more than the
  workgroup's cutoff, 1 TB by default (`infra/lib/agent-stack.ts:142`), and one invocation is bounded by the session
  budget and by the run budget (T18). What remains is the number of invocations: a caller who may invoke the runtime
  can start as many as they like, each with a fresh budget, and only IAM and your own billing alerts bound the total.
  Recommended: an AWS Budgets alert on the account.
- **T18 [Low, mitigated] An agent run that never ends.** The model-and-tool loop ends only when the model stops
  asking for tools, and a schedule runs it unattended. One invocation is bounded by a tool-call count (default 60) and
  a wall-clock deadline (default 780 s). Past a limit a tool call is refused with a message to answer from what exists
  (`src/network_flow_insight/core/runbudget.py:62-77`, `src/network_flow_insight/agent.py:70-107`). A model that keeps
  asking, or a model call long after the deadline, stops the invocation (`runbudget.py:73`, `:79-82`). A scheduled run
  that stops still writes its report, without interpretation (`agent.py:199-208`). The stack refuses a deadline that the
  scheduled-run Lambda cannot outlast (`infra/lib/agent-stack.ts:88-92`) and sets both values on the runtime
  (`:392-393`). Setting a limit to 0 turns it off, which takes this protection away.

### Elevation of Privilege

- **T2 [Low, accepted] A caller who may invoke the runtime but not read the flow logs uses chat mode.** The runtime
  declares no authorizer, so it uses its default IAM (SigV4) inbound authentication
  (`infra/lib/agent-stack.ts:374`). The role is read-only on the estate (`:224-292`). Grant
  `bedrock-agentcore:InvokeAgentRuntime` only to people who may read the flow logs.
- **T16 [Low, accepted] Broad reads by a stolen or over-granted role.** The role names the eight EC2 describe actions
  the inventory code calls and no wildcard Describe. Those, and `pricing:GetProducts`, use `*` because IAM defines no
  resource type for them (`infra/lib/agent-stack.ts:249-257`, `:267`). `cloudwatch:GetMetricData` and
  `cloudwatch:ListMetrics` also use `*` (`:261-265`): AWS lists a `dataset` resource type for them, documented for
  OpenTelemetry metrics, and classic metric reads are not shown to be authorized against it. The prefix-list read is
  limited to prefix lists in the stack's Region, with the account segment open because AWS-managed lists belong to
  another account (`:271-275`). The Config read exists only when `configAggregatorName` is passed and is limited to
  aggregators in this account and Region (`:277-286`). `s3:GetObject` covers every object in the flow-log bucket, not
  only the `AWSLogs/` prefix (`:224`). Scope it if the bucket holds other data.

## Controls

| Control | Where |
|---|---|
| One SELECT only, table allowlist, deny list, LIMIT cap | `src/network_flow_insight/core/sqlsafe.py:91-148` |
| Raw-table statements must carry literal start and end dates inside the estimated window | `src/network_flow_insight/core/sqlsafe.py:113-117`, `:222-259`; `src/network_flow_insight/tools/query_raw.py:27-32` |
| Cost gauge: estimate, per-query ceiling (default 5 USD), per-session budget (default 25 USD) | `src/network_flow_insight/core/athena.py:223-226`, `:289-296`; `src/network_flow_insight/config.py:67-68` |
| Per-invocation run budget: tool calls and wall-clock time, a refusal message first and a hard stop after | `src/network_flow_insight/core/runbudget.py:62-82`; `src/network_flow_insight/agent.py:70-107`; `infra/lib/agent-stack.ts:88-92`, `:392-393` |
| Per-query bytes-scanned cutoff on the Athena workgroup | `infra/lib/agent-stack.ts:82-85`, `:142` |
| Amazon Bedrock Guardrail on the model; the agent will not start without one | `src/network_flow_insight/agent.py:40-59`; `infra/lib/agent-stack.ts:165`, `:195-197` |
| Figures in a report narrative must appear in the findings | `src/network_flow_insight/tools/render_report.py:51`; `src/network_flow_insight/core/grounding.py:76` |
| Closed list of dimensions; days parsed as ISO dates | `src/network_flow_insight/toolset.py:42-62`, `:103-104`, `:216` |
| Read-only execution role; ARN-scoped writes | `infra/lib/agent-stack.ts:224-315` |
| Runtime role trust conditions | `infra/lib/agent-stack.ts:212-216` |
| Report bucket: public access blocked, TLS, versioning, access logs | `infra/lib/agent-stack.ts:103-118` |
| No listening socket in local or MCP mode (stdio only) | `src/network_flow_insight/mcp_server.py` |
| Intent file read with `yaml.safe_load` | `src/network_flow_insight/core/intent_schema.py:83` |
| Non-root container, pinned dependencies | `Dockerfile:21-22`; `requirements.txt` |

## MCP server controls

The stdio MCP server exposes the read tools and `render_report`, which writes only under the reports directory. It
opens no listener. The host's model chooses which tool to call and with which arguments, so the tool layer validates
them: dimensions are allowlisted, days are parsed as dates and SQL passes the gate above. Rate limiting is the host's
responsibility.

## Key management

One customer-managed KMS key with automatic rotation encrypts the report bucket by default, Athena results, the
invoker's log group and the notification topic (`infra/lib/agent-stack.ts:96`). The runtime's own log group is
created by the service and is not encrypted by this stack. Grant decrypt only to the runtime role and to people who
read reports.

## What this is not

An attestation. The report is evidence for a governance conversation and states its blind spots.
