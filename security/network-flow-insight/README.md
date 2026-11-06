# network-flow-insight

**Where does my data go, and is that what I intended?**

network-flow-insight reads VPC Flow Logs that already sit in Amazon S3, runs cost-aware Amazon Athena queries
over them, and produces an evidence pack: what leaves to the internet and by which path, what crosses Regions,
how AWS services are reached (NAT gateway, gateway endpoint or interface endpoint), what moves between VPCs,
and what is rejected. It reconciles its figures against the gateways' own CloudWatch metrics (and optionally
billing), states how confident it can be given your flow-log format and inventory, and lays out the
architecture options the evidence supports. It never changes anything in your environment.

It is for platform, network and security teams who need a report they can take into an architecture or risk
discussion, and, once a baseline is agreed, a drift report against it.

> **Not production-ready.** This is sample code for evaluation and extension, published as a prototype. It is
> not a supported product and has not had the testing, hardening or review that production use needs.
> This is sample code, for non-production usage. You should work with your security and legal teams to meet your organizational security, regulatory and compliance requirements before deployment.
> Review the code and its IAM permissions, try it in a non-production account first, and add your own controls
> (alarms, budgets, access reviews) before relying on it.
> "Status: what has been tested" below lists what has and has not been checked.

## What it answers

| Question | Where |
|---|---|
| What left the estate last week, by destination and path? | Sections 2 and 3 |
| How much S3 and DynamoDB traffic crosses NAT? Which subnets lack a gateway-endpoint route? Which interface endpoints exist but are not used? | Section 4 |
| What crosses VPCs or Regions? | Section 5 |
| What share of NAT traffic is AWS-bound, and does the total tie out to the gateway's own metrics? | Sections 6 and 13 |
| Who are the biggest talkers, what is the weekday/weekend and peak-hour shape, what grew? | Sections 7, 8, 11 |
| Is egress still what we agreed? What would enforcing the baseline block? | `nfi drift`, `nfi what-if` |

Every figure is computed by code, never by the model, and every report carries the window, tier, inventory
provider, tables, scan cost, reconciliation verdict and the query and execution ID behind the figures.

## Try it in five minutes, no AWS access

```bash
make install
make demo          # or: .venv/bin/nfi demo
```

`nfi demo` generates a deterministic synthetic estate (flow logs in the standard `AWSLogs/` layout, inventory,
metrics and billing extracts), runs the same pipeline against DuckDB instead of Athena, and writes a layered
report to `./reports/<window>/` (`report.md`, `report.html`, `diagram.svg`, `data/`). Add `--tier basic
--no-inventory` to see what a thin flow-log format and no inventory give you.

## Run it on your own flow logs

Hard requirements. Nothing else is needed.

1. VPC Flow Logs delivered to an S3 bucket (text or Parquet; default or custom format).
2. Amazon Athena and an AWS Glue table over the bucket, or opt in to let the agent create one.
3. Read-only credentials to the account that owns the bucket.
4. A model: Amazon Bedrock for the packaged agent, or your assistant's own model over MCP.

```bash
pip install -e ".[cli]"
export NFI_AWS_REGION=eu-west-2 NFI_FLOW_LOG_BUCKET=my-flow-logs \
       NFI_FLOW_LOG_DATABASE=default NFI_FLOW_LOG_TABLE=vpc_flow_logs \
       NFI_ATHENA_WORKGROUP=primary NFI_ATHENA_RESULTS_LOCATION=s3://my-athena-results/ \
       GUARDRAIL_ID=<guardrail id> GUARDRAIL_VERSION=1
nfi probe                      # tier, inventory provider, coverage, scan estimate; runs no analysis query
nfi report                     # last 7 complete days; the agent writes the interpretation
nfi report --no-model          # same figures, no model
nfi chat                       # ask follow-up questions
```

The aggregate table lives in an agent-managed Glue database (`nfi_agent` by default). It does not exist until
you allow it: add `--create-resources` once. If you have no flow-log table, `nfi create-table` shows the plan
(projection DDL over the bucket, a workgroup) and creates it only with `--confirm`.

Settings come from environment variables (`NFI_<NAME>` for every field in `src/network_flow_insight/config.py`)
or `~/.nfi.toml`. Credentials come from the standard AWS credential chain.

### Scan cost

The raw table is scanned **once per window**. A single Athena statement turns the window into a compact
Parquet aggregate; every section and every follow-up question reads the aggregate. Before each query the agent
shows the estimated bytes and cost from S3 object sizes, afterwards the actual bytes scanned and a running
total. Above `NFI_SCAN_CEILING_USD` it asks (interactive) or skips and records the skip (scheduled). A hard
per-session budget stops everything. Trend questions use CloudWatch metrics and scan nothing. Switching your
flow logs to Parquet with Hive-compatible, hourly prefixes lowers the cost of every future window.

## Capability tiers

Confidence depends on the flow-log fields and the inventory you can supply. The probe assigns a tier and every
report states it.

| Tier | Requires | Authoritative | Inferred or unavailable |
|---|---|---|---|
| Basic, no inventory | default fields | volumes, ports, accept/reject, per account and Region | which interface is a NAT gateway (inferred); gateway-endpoint traffic cannot be told from NAT; endpoint effectiveness unavailable |
| Basic with inventory | default fields + provider A, B or C | path class from interface role and route tables; NAT counted once and attributed to workloads | interfaces deleted since the window; original addresses behind NAT |
| Enhanced | + `vpc-id subnet-id az-id flow-direction pkt-srcaddr pkt-dstaddr` | independence from inventory age; original addresses behind NAT | service naming by CIDR match |
| Full | + `traffic-path pkt-src-aws-service pkt-dst-aws-service region` | path and service name from the record | nothing material |

Below Full, the report gives the exact custom format string to enable and the delivery options (Parquet,
Hive-compatible prefixes, hourly partitions) to set next time you recreate the flow log.

Inventory providers: **A** Amazon EC2 in the current account (eight `ec2:Describe*` calls, `ec2:GetManagedPrefixListEntries`), **B** an AWS Config aggregator
you can reach (hosted: one in the stack's account and Region, named with `-c configAggregatorName=<name>`), **C** a JSON file from `scripts/collect_inventory.py` (run it with whatever already reaches
your accounts, then set `NFI_INVENTORY_FILE`), **D** none, in which case forwarding interfaces are inferred
from the data and labelled so. Large estates often start at D.

## The reconciliation ladder

NAT totals are measured on the gateways' own interfaces. A NAT gateway logs every flow twice, and its own private
address is on every record: once between the workload and the NAT address (the workload-side, untranslated leg;
the real remote is in `pkt-srcaddr`/`pkt-dstaddr`), and once between the NAT address and the remote (the
internet-side, translated leg). Totals count the translated leg only, so each byte counts once; workloads are named
from the untranslated leg. The report never shows NAT composition shares until the total reconciles on at least
one rung:

1. **In-data leg check** (always): translated bytes against untranslated bytes plus any records with no known NAT
   address, on each NAT interface. Near 1 is good; well below 1 means a NAT address is missing from the filter;
   well above 1 means a non-NAT address is in the filter. Unsolicited inbound to the NAT addresses (internet scans,
   which a public NAT gateway attracts all the time) matches no outbound translation; it is reported separately and
   kept out of every total, as the gateway's own metrics keep it out.
2. **Gateway metrics** (when CloudWatch metrics are reachable from the account the agent runs in): the translated
   leg against `BytesOutToDestination + BytesInFromDestination`. Near 2 means both legs are counted.
3. **Cost and Usage Report** (local runs, when you supply a read-only role; the hosted deployment does not run this
   rung). The report states the account set compared, because account coverage is the commonest cause of a gap.
4. **Reference figure** you type in (`--reference-bytes`), for example a billed NAT total for the window.

The report names the rungs used and the rungs unavailable, with the reason.

## Use it from your assistant (MCP)

`nfi mcp` serves the same tools over stdio, with no model of its own. Your assistant's model drives it, guided
by `skill/SKILL.md` (Agent Skills format). Nothing listens on a network socket.

```jsonc
// Kiro CLI: .kiro/settings/mcp.json     Cursor: .cursor/mcp.json     Amazon Q Developer: ~/.aws/amazonq/mcp.json
{ "mcpServers": { "network-flow-insight": {
    "command": "nfi", "args": ["mcp"],
    "env": { "NFI_AWS_REGION": "eu-west-2", "NFI_FLOW_LOG_BUCKET": "my-flow-logs",
             "NFI_FLOW_LOG_TABLE": "vpc_flow_logs", "NFI_ATHENA_WORKGROUP": "primary",
             "NFI_ATHENA_RESULTS_LOCATION": "s3://my-athena-results/" } } } }
```

```bash
# Claude Code
claude mcp add network-flow-insight -e NFI_AWS_REGION=eu-west-2 -e NFI_FLOW_LOG_BUCKET=my-flow-logs -- nfi mcp
```

```toml
# Codex: ~/.codex/config.toml
[mcp_servers.network-flow-insight]
command = "nfi"
args = ["mcp"]
env = { NFI_AWS_REGION = "eu-west-2", NFI_FLOW_LOG_BUCKET = "my-flow-logs" }
```

Add `"--demo"` to the arguments to try it on the synthetic estate. Copy `skill/SKILL.md` into your assistant's
skills directory so it follows the method (probe first, state the tier, figures only from tools, reconcile
before shares, state blind spots).

## Hosted deployment (Amazon Bedrock AgentCore Runtime)

The same agent runs on Amazon Bedrock AgentCore Runtime in the account that owns the bucket, with an EventBridge
Scheduler rule for a weekly describe report or a drift report, delivered to an S3 bucket with an optional
notification.

```bash
make deploy CONTEXT="-c flowLogBucketName=my-flow-logs -c flowLogDatabase=default -c flowLogTable=vpc_flow_logs \
  -c scheduleDescribe='cron(0 6 ? * MON *)' -c notificationEmail=team@example.com"
nfi chat --remote              # with NFI_AGENTCORE_RUNTIME_ARN set to the RuntimeArn output
```

The runtime artifact is the container built from the `Dockerfile` (needs a container engine on the machine that
runs `cdk deploy`; with Finch, set `CDK_DOCKER=finch`). Without one, build a direct-code package instead and add `-c artifact=code`:

```bash
python infra/build_runtime_zip.py        # arm64 wheels for Python 3.12 -> infra/dist/runtime.zip
make deploy CONTEXT="-c artifact=code -c flowLogBucketName=... "
```

In hosted mode the inventory file, the intent file and a pinned `ip-ranges.json` can live in S3: pass
`-c inventoryFile=s3://bucket/key -c intentFile=s3://bucket/key -c ipRangesFile=s3://bucket/key` (the role gets
read access to exactly those objects). The environment variables are `NFI_INVENTORY_FILE`, `NFI_INTENT_FILE`
and `NFI_IP_RANGES_FILE`, and each accepts a local path or an `s3://` URI.

**What the hosted deployment does not run.** The Cost and Usage Report and Resolver-log rungs read tables that often
sit in another account, through a read-only role you supply. They run in local runs (the `NFI_CUR_*` and
`NFI_RESOLVER_*` settings); the stack does not pass those settings and the hosted role has no `sts:AssumeRole`.

**Limits.** A run cannot loop without bound. One agent invocation (a scheduled run, or one chat turn) may make 60 tool
calls and run for 780 seconds by default. Past either limit a tool call is refused with a message telling the model to
answer from what it has; if the model keeps asking, the invocation stops. A scheduled run that stops this way still writes
its report, without the model's interpretation. Set the limits with `-c maxToolCalls=<n>` and `-c runDeadlineSeconds=<n>`
(environment variables `NFI_MAX_TOOL_CALLS` and `NFI_RUN_DEADLINE_SECONDS`; `0` turns a limit off; the deadline can be at
most 800 because the scheduled-run Lambda waits 880 seconds). The Athena workgroup also stops any single query that scans
more than 1 TB; change that with `-c athenaBytesScannedCutoff=<bytes>` (minimum 10,000,000). Repeated invocations by a
caller who may invoke the runtime are bounded only by IAM and your own billing alerts; set a budget alert on the account.

The stack (`infra/lib/agent-stack.ts`) creates the execution role, a KMS key, the report bucket (encrypted,
versioned, public access blocked, TLS only, access logged), the agent Glue database and Athena workgroup, an
Amazon Bedrock Guardrail, the AgentCore Runtime (arm64 container, non-root), the Scheduler rule and an invoker
Lambda that calls `InvokeAgentRuntime` and fails when the runtime reports a failure (it is never retried, so a
failed run raises the alarm and does not start a second run), plus alarms on failures and latency. The runtime is declared with
the CloudFormation resource `AWS::BedrockAgentCore::Runtime` (deployed and invoked in eu-west-2 during the build). If
it is not yet available in your Region, deploy the rest and create the runtime with `agentcore deploy` using the role
and artifact in the stack outputs.

## Permissions

Customer-environment permissions are read-only: `s3:GetObject` and `s3:ListBucket` on the flow-log bucket,
Athena query actions on the agent workgroup, `glue:Get*`, eight named `ec2:Describe*` actions (the calls inventory
provider A makes; no wildcard Describe), `cloudwatch:GetMetricData` and `ListMetrics`, and `pricing:GetProducts`. The hosted
role has no `sts:AssumeRole`: the Cost and Usage Report and Resolver-log rungs run only in local runs. The EC2 describe actions and
`pricing:GetProducts` have no IAM resource type, so they stay on `Resource: "*"`. The two CloudWatch actions list a
`dataset` resource type that AWS documents for OpenTelemetry metrics; the agent reads classic metrics, which are not shown
to be authorized against it, so they stay on `*` too. `ec2:GetManagedPrefixListEntries` is limited to prefix lists in the stack's Region (the account segment is open
because AWS-managed lists belong to another account). `config:SelectAggregateResourceConfig` is granted only when
you pass `-c configAggregatorName=<name>`, and then only on aggregators in the stack's account and Region. Writes go
only to resources the agent creates. See [SECURITY.md](SECURITY.md).

## Status: what has been tested

This is a prototype. It has been run against a synthetic estate with known answers, and against real VPC Flow Logs
from a small test VPC (one public NAT gateway with a secondary address, gateway and interface endpoints, an internet
gateway, VPC peering and a Transit Gateway), both locally and on Amazon Bedrock AgentCore Runtime. On that data the
NAT leg check reads about 1.00, the NAT gateway's CloudWatch metrics agree with the flow-derived legs to within 5%,
and every path class was classified correctly. Also tested on that data:

- **A settled day.** Over one complete UTC day, a local run and a hosted scheduled run produced identical figures,
  the cost estimate equalled the bytes Athena scanned, and a later run reused the settled aggregate with identical
  figures.
- **Three flow-log setups on the same VPC.** Custom full format as plain text; the same format as Parquet with
  Hive-compatible, hourly partitions; and the default version 2 format, with inventory and without it (the
  inventory-free provider D found the NAT gateway and the Transit Gateway attachments). All counted totals agreed.
- **NAT gateway secondary addresses.** The NAT scope lists the primary and secondary private addresses.

Not yet tested, so treat these as unverified:

- **Cost and Usage Report rung.** Not run against a real CUR. The billed-GB unit (decimal or binary) is assumed, not checked.
- **Traffic through a secondary NAT address.** The secondary address is listed, but in testing it carried no traffic.
- **Other estates.** AWS Config aggregator inventory (provider B), private NAT gateways, and cross-account flow logs.
- **Agent reliability.** The model-driven behaviour was evaluated with 12 scripted scenarios, each run once (the
  harness repeats a case only when its result is borderline). Ten passed. Two did not:
  - Asked for every raw row, the agent declined correctly, but its suggested example ("show me 50 raw rows") held a
    figure no tool had returned, so the strict figure check failed it.
  - A resource name carrying a planted instruction was stopped by the Amazon Bedrock Guardrail, so the instruction
    was not followed, but the user received a generic block message and no answer. With the guardrail off, the model
    treated the same text as data and did not act on it. That is one run with one phrasing.

  Figures in chat answers are checked after the fact, and any figure no tool returned is flagged in the answer. The
  check compares digits only, regardless of unit or label, so a figure can pass because the same digits appear
  elsewhere in a tool result. Treat the sample as evidence of behaviour, not as a measure of reliability.

## What it is not

Not an attestation: the report is evidence, reproducible from stored queries, with its blind spots listed
(DNS resolver, instance metadata, time sync, DHCP, licence activation and the VPC router address are not
logged; records are 1 or 10 minute aggregates; interfaces without a flow log and partitions the table cannot
see are invisible). Not a performance tool, a threat detector, or an incident investigator, and it makes no
changes. It recommends options and does not rank them.

## How it relates to `sample-cost-analyzer-agent`

That sample is a billing agent that reaches into flow logs for data-transfer cost drivers and expects a custom
log format. This one is a flow-log specialist that reaches into billing: it works with the format you already
have, classifies paths by interface role and route table, scopes NAT traffic so bytes count once, reconciles
to gateway metrics, and keeps an intent baseline for drift. They can sit side by side.

## Development

```bash
make test       # unit and integration tests; the synthetic estate gives byte-exact ground truth
make lint security synth
```

To exercise the real Athena and hosted paths in a test account that has no VPCs, write the synthetic flow
logs with `nfi demo-estate DIR`, `aws s3 sync DIR/s3/ s3://<test-bucket>/`, and point `NFI_FLOW_LOG_BUCKET` at
it (use `nfi create-table` for the projection table). `DIR/ground_truth.json` holds the exact expected figures.

Build the bundle for publication from a clean clone: local build output (`infra/node_modules`, `infra/cdk.out`,
`infra/dist`, `*.egg-info`) is git-ignored but would be copied from a working tree.

Layout: `src/network_flow_insight/` (`core/` engine, `tools/` one tool per file, `toolset.py` model-facing
bindings, `agent.py`, `mcp_server.py`, `agentcore_app.py`, `cli.py`, `demo/`), `skill/`, `scripts/`, `infra/`,
`tests/`. The intent behind every design choice is in `.kiro/specs/network-flow-insight/`.

## License

MIT-0. See the `LICENSE` file at the repository root.
