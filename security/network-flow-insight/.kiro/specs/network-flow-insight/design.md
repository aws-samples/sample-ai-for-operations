# network-flow-insight — Design

This document says how the intent in `requirements.md` is built. Section numbers in brackets refer
to that file.

## 1. Architecture

One Python package, `network_flow_insight`, with a tool layer that does all the work and three thin
ways in (a Strands agent, an MCP server, a CLI). Pattern #1 (Amazon Bedrock AgentCore Runtime) is the canonical deployment; the same agent
runs locally for development, evaluation and ad hoc use.

```
                    ┌──────────────────────────────────────────────────────────┐
  nfi report/chat   │  Strands agent (agent.py)                                 │
  (local CLI) ─────▶│  model: Amazon Bedrock, Guardrails attached              │──┐
                    │  system prompt: src/prompts/system_prompt.md              │  │
  AgentCore Runtime │  decides what to query, interprets, explains              │  │
  (hosted, sched.) ▶│  never computes a number                                  │  │
                    └──────────────────────────────────────────────────────────┘  │
                                                                                  ▼
  Kiro CLI / Claude Code / Codex / Cursor / Q Developer    ┌────────────────────────────────┐
  (their model + our SKILL.md) ───── MCP stdio ───────────▶│  Tool layer (src/tools/*.py)    │
                                                           │  data retrieval ─ boto3, Athena │
                                                           │  precision ─ pure Python        │
                                                           └──────────────┬─────────────────┘
                                                                          ▼
   S3 flow-log bucket ─ Athena ─ Glue ─ EC2/Config inventory ─ CloudWatch ─ Pricing ─ (CUR)
   + agent-managed: Glue DB, workgroup, results prefix (aggregate Parquet), report bucket
```

### 1.1 Why this shape (recap of decisions already taken)

- Flow-log specialist that reaches into billing; the public repo already has a billing agent that
  reaches into flow logs (`sample-cost-analyzer-agent`). Different centre of gravity, stated in the
  README.
- Not a DevOps Agent skill for v1 (audience, artefact, and a custom tool layer needed anyway); the
  MCP server keeps that door open.
- AgentCore + Gateway (#2) rejected: one agent, one tool set, same process. Gateway adds an
  endpoint and auth for no capability.
- Local run is pattern #1 minus the runtime wrapper, not a separate architecture.

### 1.2 Request flow (describe mode)

1. `probe` → schema, partitioning, coverage, inventory provider, tier, `SKIPDATA` share.
2. `estimate_scan` for the aggregate pass → cost gauge → confirm or ceiling.
3. `build_aggregate` → one Athena CTAS over the window into Parquet under the agent's results prefix,
   registered as a table in the agent-managed Glue database. Everything after this reads the
   aggregate.
4. Inventory → `classify_path`, `classify_destination`, `pair_conversations`.
5. `nat_scope` + `nat_leg_check` (+ metrics, CUR, reference where available) → `reconcile`.
6. Precision tools produce every section's figures; `price_context` attaches rates to options.
7. Agent composes prose around the figures; `render_report` writes the layered report and data pack.

Chat mode skips 3 if an aggregate for the window already exists, and routes questions through
`query_aggregate` (cheap) or, when the aggregate cannot answer, `query_raw` (gauged).

## 2. Package layout

```
network-flow-insight/
├── src/network_flow_insight/
│   ├── agent.py                 # Strands agent; local entry and AgentCore entry share it
│   ├── agentcore_app.py         # BedrockAgentCoreApp wrapper (hosted mode only)
│   ├── cli.py                   # `nfi` command: probe | report | chat | intent | drift | what-if | create-table | demo | mcp
│   ├── mcp_server.py            # stdio MCP server exposing the session tools; no model, no loop
│   ├── toolset.py               # ToolSession: model-facing bindings of the tools (short arguments, session state)
│   ├── analysis.py              # the describe-mode workflow as calls to the tool layer
│   ├── aws_backend.py           # real-AWS wiring (S3, Athena, Glue, CloudWatch, Price List)
│   ├── config.py                # all environment-derived settings; nothing else reads os.environ
│   ├── prompts/system_prompt.md
│   ├── core/                    # shared engine used by tools (not tools themselves)
│   │   ├── athena.py            # query runner, result paging, execution-ID capture, cost gauge
│   │   ├── sqlsafe.py           # SQL validation (sqlglot): SELECT-only, table allowlist, predicates, LIMIT
│   │   ├── tablescheme.py       # partition scheme of the raw table, window predicates, projection DDL
│   │   ├── aggregate.py         # the aggregate SELECT
│   │   ├── s3layout.py          # AWSLogs/ prefix walker, size estimation, field detection
│   │   ├── inventory/           # providers A (ec2), B (config aggregator), C (file); D lives in tools/
│   │   ├── ipranges.py          # ip-ranges.json loader, most-specific match
│   │   ├── intent_schema.py     # pydantic models for intent.yaml
│   │   ├── grounding.py         # check that prose contains no figure absent from the findings
│   │   ├── runbudget.py         # per-invocation tool-call and wall-clock budget (pure; the agent wraps it in hooks)
│   │   └── units.py             # bytes → decimal GB/TB, labelled
│   ├── tools/                   # one tool per file; pure functions that take and return data (§3)
│   └── demo/                    # synthetic estate, generator, DuckDB engine (nfi demo and CI)
├── skill/
│   └── SKILL.md                 # Agent Skills format; the method for MCP hosts
├── scripts/
│   └── collect_inventory.py     # provider C collection script (read-only describe-* calls → JSON)
├── infra/                       # CDK v2 (TypeScript)
│   ├── bin/app.ts
│   ├── lib/agent-stack.ts       # role, agent-managed bucket/Glue DB/workgroup, Guardrail, Runtime, Scheduler
│   ├── lambda/invoker.py        # Scheduler target: calls InvokeAgentRuntime, fails if the runtime reports a failure
│   └── cdk.json
├── tests/
│   ├── unit/                    # precision tools tested to the byte against generator ground truth
│   ├── integration/             # agent loop with a scripted model; MCP and hosted-handler parity
│   └── fixtures/generator.py    # re-exports the generator in src/network_flow_insight/demo/
├── Dockerfile                   # arm64, python:3.12-slim, non-root
├── pyproject.toml               # package metadata; extras: [cli] adds strands; [dev] adds duckdb and test tools
├── requirements.txt
├── Makefile                     # install, demo, test, lint, security, synth, deploy
├── intent.example.yaml
├── SECURITY.md
└── README.md
```

Dependencies are split so the MCP route stays light: base install gives `boto3`, `mcp`, `sqlglot`,
`pydantic`, `pyyaml`, `pyarrow`; the `[cli]` extra adds `strands-agents`. Demo mode needs `duckdb` (part of
the `dev` extra) to run the aggregate SQL locally over the generated flow logs.

## 3. Tool classification

No tool runs a model. Data retrieval tools call AWS and return structured data. Precision tools are
pure Python over structured data and are the only source of any number in any output.

The functions in `tools/` take and return data, which makes them testable to the byte. A model should not
pass tables around, so `toolset.ToolSession` holds the session state (window, aggregate rows, inventory,
classification, findings) and exposes the same tools with short arguments: days, dimension names, SQL.
Strands, the MCP server and the CLI all use `ToolSession`, so the three surfaces return the same figures.

### 3.1 Data retrieval tools

| Tool | Does | Input → Output |
|---|---|---|
| `probe_table` | Glue schema, partition scheme (projection vs enumerated), partition list, sample of `log_status` | database, table, window → `{fields, tier_fields, projection, partitions_present, skipdata_share}` |
| `list_log_prefixes` | Walk `AWSLogs/` under the configured bucket only; account, Region, day prefixes and object sizes | bucket, window → `{accounts, regions, days, bytes_by_partition}` |
| `estimate_scan` | Bytes under partitions a query would touch (from `list_log_prefixes`), at the Region's Athena rate | partitions → `{bytes, gb, cost}` (pricing from `get_prices`) |
| `run_athena` | Execute validated SQL, wait, page results, capture execution ID and `DataScannedInBytes` | sql, workgroup → `{rows, execution_id, scanned_bytes}` |
| `build_aggregate` | CTAS from raw table into Parquet aggregate for the window | window, tier_fields → `{aggregate_table, execution_id, scanned_bytes}` |
| `query_aggregate` | Validated SELECT against the aggregate only | sql → rows (via `run_athena`) |
| `query_raw` | Validated SELECT against the raw table, gauged | sql → rows (via `estimate_scan` then `run_athena`) |
| `get_inventory` | Interfaces with roles, NAT gateways and all private addresses, endpoints, route tables, subnets, VPC CIDRs, TGW attachments, prefix lists, from provider A, B or C | provider config → inventory JSON (documented schema shared with provider C) |
| `get_gateway_metrics` | CloudWatch `GetMetricData` for NAT, endpoint and TGW bytes, per gateway, for a window; one call per Region in the agent's account (source accounts appear only if the account is already a monitoring account) | gateways, window → `{gateway_id: bytes}` or `unavailable` |
| `get_ip_ranges` | `ip-ranges.json` over HTTPS, cached; managed prefix lists from inventory | → structured range index |
| `get_prices` | Price List API: NAT processing, interface endpoint processing, Regional and inter-Region transfer, data transfer out, Athena per TB, per Region | region → rate table |
| `query_cur` | Validated SELECT against CUR via Athena, optionally through an assumed role | window, account set → usage-type totals or `unavailable` |
| `query_resolver_logs` | Validated SELECT against Resolver query-log table, IP → most recent query name | ips, window → `{ip: names}` or `unavailable` |
| `create_table` | Opt-in: Glue database, projection table over `AWSLogs/`, workgroup with results location; tags `agent-managed: "true"` | bucket, accounts, regions → identifiers. Only write to anything the agent did not create: none. |
| `write_report` | Put rendered report and data pack to local path or agent report bucket | artefacts → locations |

### 3.2 Precision tools

| Tool | Does | Input → Output |
|---|---|---|
| `assign_tier` | Tier from fields present and provider available [§6] | fields, provider → `{tier, available_sections, unavailable_sections, upgrade_recommendation}` |
| `check_coverage` | Partitions present vs prefixes present; uncovered accounts/regions/days; `SKIPDATA` and `NODATA` shares; gateways with no records in the window | probe, prefixes, aggregate, inventory → coverage findings |
| `classify_path` | Interface role → route table → `traffic-path`; records method used | aggregate rows, inventory → rows with `path_class, method` |
| `detect_forwarding_interfaces` | Provider D heuristics (§5) | aggregate rows → `{interface_id: {role_guess, confidence, evidence}}` |
| `classify_destination` | VPC CIDRs → named networks → ip-ranges most-specific → prefix lists → buckets; EC2/AMAZON-only → "AWS-hosted, unverified"; RFC1918 unknown → "private, unnamed" | remote ips, inventory, intent, ranges → `{ip: {bucket, service, method}}` |
| `pair_conversations` | Pair legs into client→server by server-port inference; label ambiguous | aggregate rows → conversations |
| `nat_scope` | Split NAT-interface rows into translated (internet-side), untranslated (workload-side) and unmatched legs (§4.3); remote = the non-NAT address on the translated leg; workloads from the untranslated leg; direction from which side the NAT address is on | aggregate rows, NAT addresses → NAT flows |
| `nat_leg_check` | Translated-leg bytes vs untranslated plus unmatched bytes per NAT interface; ratio and diagnosis | aggregate rows, NAT addresses → `{interface: {ratio, diagnosis}}` |
| `aggregate_by` | Sum bytes/flows/conversations by any dimension set | rows, dims → table |
| `top_n` | Rank with share of total | table, n → ranked table |
| `period_compare` | Two windows: deltas, new, gone, share of growth | table_a, table_b → comparison |
| `time_profile` | Per-day series, weekday/weekend means, peak day, peak hour (when hourly data) | rows → profile |
| `reconcile` | Flow-derived vs each available rung; ratio, tolerance test, caution flags, rung list | totals, metrics, cur, reference → reconciliation |
| `endpoint_effectiveness` | Interface endpoints present vs same service's prefixes on the VPC's NAT path; subnets lacking gateway-endpoint routes with S3/DynamoDB on NAT; cross-Region S3/DynamoDB on NAT | classified rows, inventory → findings |
| `gateway_utilisation` | Bytes per NAT gateway in window; idle threshold | NAT flows, inventory → table |
| `enrich_conversations` | Attach consumer (subnet, or /24) and provider (bucket, service or network) to each conversation; the keys shared by baseline, drift and what-if | conversations, destinations, inventory → enriched conversations |
| `price_context` | Rate × volume per path class per Region, presented as context for options | volumes, rates → option evidence |
| `draft_intent` | Baseline from observed conversations with evidence per entry | conversations, classifications → intent YAML |
| `drift` | Observed vs committed intent: matched, new, stale, path-changed | conversations, intent → drift findings |
| `what_if` | Share of bytes and conversations outside intent, by bucket and originating workload | conversations, intent → impact table |
| `to_units` | Bytes → labelled decimal GB/TB; never silently | bytes → `{value, unit}` |
| `render_report` | Markdown + HTML (summary, sections, appendices, reproducibility), data pack (CSV, JSON, edge list), static dependency diagram | all findings → artefacts |

### 3.3 The rule the system prompt enforces

> You decide what to investigate and how to explain it. You never count, sum, compare, rank or
> compute a percentage or a cost in prose. Every figure you state must appear in a tool result in
> this session. If you need a number that no tool has produced, call the tool. Before stating any
> NAT composition share, state the reconciliation result beside it.

## 4. SQL strategy

### 4.1 Partition projection (create path and probe)

Create-path DDL uses projection over the standard layout, with the account and Region as enums
discovered by `list_log_prefixes` and `day` as a date range. The partition columns are `part_account`,
`part_region` and `day`; they deliberately do not reuse `account_id` or `region`, which are also flow-log
field names, because Athena rejects a partition column that duplicates a data column.

```sql
CREATE EXTERNAL TABLE nfi_flow_logs (...default or detected fields...)
PARTITIONED BY (part_account string, part_region string, day string)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '
LOCATION 's3://<bucket>/AWSLogs/'
TBLPROPERTIES (
  'skip.header.line.count'='1',
  'projection.enabled'='true',
  'projection.part_account.type'='enum', 'projection.part_account.values'='<discovered>',
  'projection.part_region.type'='enum',  'projection.part_region.values'='<discovered>',
  'projection.day.type'='date', 'projection.day.format'='yyyy/MM/dd', 'projection.day.range'='<first>,NOW',
  'storage.location.template'='s3://<bucket>/AWSLogs/${part_account}/vpcflowlogs/${part_region}/${day}',
  'agent-managed'='true'
);
```

The Hive-compatible layout (`aws-account-id=…/aws-region=…/year=…/month=…/day=…`, projected as integer
`p_year`, `p_month`, `p_day`), the organisation form (`AWSLogs/o-…/`) and Parquet are detected and handled with
the matching template and SerDe. Existing tables are read through their Glue schema, whatever their partition
names (`day`, `date`, or year/month/day). The probe recognises an existing
table's scheme and, for enumerated partitions, compares them with `list_log_prefixes` to produce
the coverage finding. An existing table without projection gets a recommendation, not a change.

### 4.2 The aggregate (scan once)

One CTAS per window, grouped at the finest grain the sections need, so every section is a cheap
re-aggregation:

```
day, hour (when start is present), account_id, region, interface_id,
srcaddr, dstaddr, pkt_srcaddr, pkt_dstaddr, srcport, dstport, protocol, action, log_status,
flow_direction, traffic_path, pkt_src_aws_service, pkt_dst_aws_service, vpc_id, subnet_id, az_id
(NULL when the field is absent) → SUM(bytes), SUM(packets), COUNT(*) AS records
```

Ports are normalised to keep the aggregate small: a port is stored as 0 (ephemeral) when it is 32768 or
above, or when the other side uses a port below 1024 and this side is 1024 or above. Servers on ports
below 32768 keep their exact port, and conversation pairing reads exactly one service-port side.
`log_status` is a grouping column so the `SKIPDATA` and `NODATA` shares come from the aggregate.

Stored as Parquet under `<results_prefix>/nfi/aggregate/source=<tag>/window=<from>_<to>/` as table `nfi_agg_<tag>_<from>_<to>`, where `<tag>` is a short hash of the raw flow-log table (`database.table`) so tables sharing an agent database never collide and an aggregate is only reused for its own source; registered in the
agent-managed Glue database. Addresses are kept at full precision because NAT scoping, pairing and endpoint effectiveness need them;
the aggregate is still much smaller than raw because of the GROUP BY on day, hour, port and protocol. In
hosted mode the aggregate is read back from its Parquet files in S3, not through the Athena result API. When a
workgroup enforces its output location, the CTAS omits `external_location` and the table's location is read
from the Glue catalog.

Reuse across sessions: `find_aggregate` returns the registered `nfi_agg_<tag>_<from>_<to>` only if its Glue
`CreateTime` is at or after the window's settle point (end of `<to>` plus `aggregate_settle_minutes`, default
60). Otherwise, and for a window that has not settled yet, the build is versioned: table
`nfi_agg_<tag>_<from>_<to>_b<yyyymmddHHMMSS>` under `source=<tag>/window=<from>_<to>/build=<version>/`. CTAS can neither replace a
table nor write into a non-empty location, so versioning avoids any drop; versioned builds are never reused.

### 4.3 NAT scoping

A NAT gateway's interface logs every flow twice, and its private address is on every record:

| Leg | srcaddr → dstaddr | pkt-srcaddr → pkt-dstaddr | flow-direction | traffic-path |
|---|---|---|---|---|
| workload side, out | workload → NAT | workload → remote | ingress | – |
| internet side, out | NAT → remote | NAT → remote | egress | 8 |
| internet side, return | remote → NAT | remote → NAT | ingress | – |
| workload side, return | NAT → workload | remote → workload | egress | 1 |

`nat_scope.nat_leg` is the one place this rule lives. A record on a NAT interface is on the translated
(internet-side) leg when a NAT address is source or destination and the `pkt-*` address on the NAT side
is the NAT address; on the untranslated (workload-side) leg when that `pkt-*` address is someone else.
Without `pkt-*` fields the other address decides: private means workload side, so NAT to private
destinations (as with a private NAT gateway) needs `pkt-*`. Records with no known NAT address are
unmatched. The translated-leg predicate in SQL is `nat_scope.translated_leg_sql`:

```sql
SELECT CASE WHEN srcaddr IN (<nat_addrs>) THEN dstaddr ELSE srcaddr END AS remote_ip,
       CASE WHEN srcaddr IN (<nat_addrs>) THEN 'out' ELSE 'in' END AS direction,
       SUM(bytes)
FROM aggregate
WHERE interface_id IN (<nat_enis>) AND action = 'ACCEPT' AND day BETWEEN ...
  AND ((srcaddr IN (<nat_addrs>) AND pkt_srcaddr IN (<nat_addrs>))
       OR (dstaddr IN (<nat_addrs>) AND pkt_dstaddr IN (<nat_addrs>)))
GROUP BY 1, 2
```

Workloads come from the untranslated leg (`srcaddr` outbound, `dstaddr` on return) at every tier; with
`pkt-*` each workload is also paired with its real remote. The leg check compares the translated leg with
the untranslated leg plus unmatched records. Rung 2 compares the translated leg with the gateway's
`BytesOutToDestination + BytesInFromDestination`; `BytesInFromSource` and `BytesOutToSource` correspond to
the untranslated leg. Unsolicited inbound to a NAT address (an internet scan) appears on the internet side only:
`nat_scope.solicited_keys` collects `(interface, remote, remote port, protocol)` from translated outbound records,
and a translated inbound record whose key is not there is unsolicited (`nat-unsolicited-inbound`). It is reported
in `nat.scope.unsolicited` and kept out of the translated leg, the leg check and rung 2: the gateway's metrics keep
it out too (`BytesInFromDestination` equals `BytesOutToSource`, and unsolicited packets are never forwarded). The
remote's port survives the aggregate's port normalisation on both legs, so the match works on aggregate rows.

Counting: a workload interface counts its outbound bytes, and its inbound bytes unless the sender is a workload
whose own interface has records in the window (that sender's outbound already counts them). A workload that is in
the inventory but logs nothing in this table, for example in a VPC whose flow log goes elsewhere, is treated as
an outside sender, so partial flow-log coverage does not lose bytes.

Records on an interface the inventory does not know (deleted since the window) are classified from the
subnet in the record (enhanced and full formats) through that subnet's route table; their outbound bytes and
their inbound bytes from public sources are counted. `traffic-path` 1 ("through another resource in the
same VPC") also covers instance-to-instance traffic, so the cross-check accepts it for intra-VPC paths.
Records whose own `traffic-path` contradicts the current inventory are listed by inventory class, record class
and subnet with their bytes (`path_volume.crosscheck_disagreements`) and raise a caution: a route changed during
the window, or the inventory is not from the window. Their path class still comes from the inventory, so both
legs of a conversation keep one class.

### 4.4 SQL safety

The model may author SQL for chat. Every statement passes `sqlsafe` before execution: parsed with
`sqlglot`; single statement; `SELECT` only; tables restricted to the raw table, the aggregate and
(when configured) the CUR and Resolver tables; `LIMIT` capped; no `UNLOAD`, functions on the deny list rejected.
Table references are qualified with their database before execution. Failing statements are returned to the model
with the reason, never executed.

SQL that the tools build themselves follows the same discipline: database and table names pass `ident()` (letters,
digits and underscore only), and the window's dates are re-parsed by `iso_day()` at the point of use, so a value that is
not exactly a `YYYY-MM-DD` calendar date raises `ValueError` and is never written into a statement.

Partition bound. The estimate for a raw-table query is the whole requested window, so the gate accepts a raw-table
statement only if its `WHERE` (or a join condition) holds, as top-level `AND` terms, a literal start and a literal end
for the day column (for a table split into year, month and day columns, for each of the three), and both lie inside
that window. `BETWEEN`, `=`, `IN`, or a `>`/`>=` plus `<`/`<=` pair qualify. A term under `OR` or `NOT`, a comparison
with another column or a function, an unparseable literal and a one-sided range do not. The rejection names the
window and shows the form. The aggregate table is small and priced at its own size, so for it a comparison on
`day` is enough.

## 5. Provider D heuristics (no inventory)

Computed from the aggregate for the window:

1. For each `interface_id`, find the dominant local address: the address appearing most often as
   source or destination on that interface.
2. NAT gateway test first. A NAT gateway's own private addresses (one, or a small set with secondary
   addresses) are on nearly every record. Each candidate address talks to at least two public remotes
   on one leg and to private peers on the other, and the bytes of the two legs balance, overall and
   per (protocol, service port): on the internet leg the remote's port, on the workload leg the NAT
   address's own port. With `pkt-*` fields, the workload leg must also show the real remote on the NAT
   side, which makes the guess high confidence; without them it is medium.
3. Relay test. An interface whose dominant address is on nearly every record while `pkt-*` names a
   different address on its side on most of them relays traffic for others: a Transit Gateway
   attachment (private on both sides) or another forwarder. Without `pkt-*`, the same relay is found by
   what the other interfaces record: an address on most of the interface's records, with only private
   records, whose peers are main addresses of other logged interfaces that never record that address
   (they record the real peer). A server's address is recorded by its clients' own interfaces. Medium
   confidence; when its peers are not logged the relay cannot be told from a workload.
5. Otherwise, share of records on the interface where neither address is the dominant one,
   `foreign_share`. Workload interfaces: near 0. Other forwarding interfaces (NAT instance or firewall
   appliance): substantial; private on both sides suggests a Transit Gateway attachment or appliance.
6. Output a role guess with confidence (`high`, `medium`, `low`) and the evidence, plus the one
   command (`aws ec2 describe-network-interfaces --network-interface-ids …`) that confirms it.

Thresholds are configuration, tuned against the fixture, and every classification made this way is
labelled `method: inferred` in the aggregate and the report.

## 6. Intent file

`intent.yaml`, validated by `core/intent_schema.py`:

```yaml
version: 1
networks:                      # customer-named ranges the agent cannot discover
  - name: on-prem-dc1
    kind: on-premises          # on-premises | partner | saas | vpc | other
    cidrs: ["10.200.0.0/16"]
buckets:                       # optional; defaults used when absent
  - name: not-subject-to-inspection
    match: { services: ["S3", "DYNAMODB"], paths: ["gateway-endpoint"] }
    disposition: allow
  - name: candidate-for-private-path
    match: { aws_service: true, paths: ["nat"] }
    disposition: review
  - name: subject-to-inspection
    match: { default: true }
    disposition: inspect
baseline:                      # produced by `intent draft`, pruned by a human
  - consumer: { network: app-vpc-prod }       # a VPC, named network, subnet or workload
    provider: { bucket: aws-service, service: S3, port: 443, path: gateway-endpoint }
    evidence: { bytes: 123456789, conversations: 4567, first_seen: ..., last_seen: ... }
```

`drift` and `what_if` operate on `baseline`; `classify_destination` uses `networks` and `buckets`.

## 7. Report

Layered Markdown and HTML:

1. Summary page: tier and provider, window, scan cost, reconciliation verdicts, five headline
   findings, cautions.
2. Sections, in the order of [§4.1(6)].
3. Options: each with the flows that justify it, the volumes, the rates, and what it would and
   would not change. No ranking.
4. Appendices: methodology, blind spots [§8.3], every figure's query and execution ID.
5. Data pack: `series.csv`, `edges.csv`, `findings.json`, `aggregate_manifest.json`.

The dependency diagram is a static SVG generated from the same edges (consumers left, providers right, line
weight by bytes) with a built-in layout; no interactive component, no server. Interpretation text supplied by
the model is rendered only if every figure in it appears in the findings; otherwise it is left out and a
caution says so.

## 8. Deployment

### 8.1 Local

`pip install network-flow-insight[cli]`, credentials in the shell, `nfi probe`, `nfi report`.
Config via environment or `~/.nfi.toml`: bucket, database, table, workgroup, Region, model ID,
Guardrail ID, optional CUR/Resolver settings, optional role ARNs, inventory provider, ceiling, and an
optional Athena price override for operators who cannot call the Price List API. The Guardrail is required
for the model in both modes; an explicit, logged local-development override exists.
Reports to `./reports/<timestamp>/`.

### 8.2 Hosted (pattern #1)

CDK stack (`infra/lib/agent-stack.ts`) creates:

- Execution role with the read-only policy from §9 plus write scoped to agent-managed resources.
- Agent report bucket (encryption, versioning, public access blocked, TLS-only policy).
- Agent Glue database and Athena workgroup with results location in the report bucket and a bytes-scanned cutoff per
  query (default 1 TB, decimal; `-c athenaBytesScannedCutoff=<bytes>`, minimum 10,000,000).
- Amazon Bedrock Guardrail: content filters including the prompt-attack filter on input; denied topics for
  attack and detection-evasion help and for legal, medical and financial advice; sensitive-information rules
  that block AWS keys, passwords and card numbers. IP addresses are deliberately not filtered, because they are
  the data. A catch-all "anything that is not network traffic analysis" topic is not used: topic classifiers
  fire on the agent's own in-scope answers. For the same reason the attack and advice topics apply to input
  only and the attack topic is worded around evading logging and exfiltration, so the agent's own explanation that
  a rejected flow cannot be called an attack is not blocked. The blocked-input message explains that flow logs
  show accepted and rejected connections, not intent, and says what the agent does not help with. A new guardrail
  version is created whenever the definition changes.
- Chat answers are not gated before they are written, so `agent.answer_figures_not_from_tools` checks them after
  the fact against every tool result in the conversation and the user's own prompt, and the caller appends a
  caution. The report narrative keeps its stronger gate (figures that fail are left out).
- AgentCore Runtime hosting the arm64 image, with the execution role, declared with the CloudFormation
  resource type `AWS::BedrockAgentCore::Runtime` so the stack does not depend on a particular CDK minor
  version. The runtime artifact is the container image (default) or, for builders without a container engine,
  a direct-code package built by `infra/build_runtime_zip.py` (`-c artifact=code`; arm64 wheels, Python 3.12). A runtime's artifact type cannot change in place, so the runtime name
  includes the artifact type and a switch replaces the runtime. The runtime creates its own log group; the role may
  create and write groups under the runtimes prefix, and the stack does not declare that group. A scheduled run whose agent
  fails still renders the report from the findings, without interpretation.
  The inventory file, intent file and a pinned `ip-ranges.json` can be given as `s3://` URIs (read-only). Where that resource is not yet available in the deployment Region, deploy the rest of the stack
  and create the Runtime with `agentcore deploy` using the role and image in the stack outputs.
- EventBridge Scheduler rule → small Lambda that calls `InvokeAgentRuntime` with a fixed payload
  (`{"mode": "describe"}` or `{"mode": "drift"}`) → report lands in the bucket → optional SNS
  notification. The Lambda contains no logic beyond the call and a check of the reply (§10).
- The run budget (`core/runbudget.py`) bounds one invocation: Strands hooks count tool calls (`BeforeToolCallEvent`) and
  check the clock (`BeforeModelCallEvent`), and a fresh budget starts with each invocation (`BeforeInvocationEvent`). Past
  a limit a tool call is cancelled with a message that tells the model to answer from what it has; after five further
  refusals, or a model call later than the deadline plus 60 s, the invocation raises `RunBudgetExceeded`, which the
  scheduled path already handles by rendering the report without interpretation. `-c maxToolCalls=<n>` and
  `-c runDeadlineSeconds=<n>` set `NFI_MAX_TOOL_CALLS` and `NFI_RUN_DEADLINE_SECONDS` on the runtime; a deadline above 800 s
  is refused at synthesis because the Lambda waits 880 s.

`agentcore_app.py` wraps the same `agent.py` with `BedrockAgentCoreApp`; the payload selects
mode and window. Interactive hosted use is through `InvokeAgentRuntime` from the CLI (`nfi chat
--remote`).

### 8.3 MCP and skill

`nfi mcp` starts the stdio server exposing the session tools (`probe`, `estimate_scan`, `describe`,
`get_section`, `aggregate`, `classify_addresses`, `query_aggregate`, `query_raw`, `metric_trend`,
`intent_draft`, `drift`, `what_if`, `render_report`, `to_units`), which are the §3 tools with short arguments. `SKILL.md`
carries the method: probe first; state tier; build the aggregate once; scope NAT; run the leg
check before quoting shares; figures only from tools; state blind spots. README shows the
registration snippet for each host.

### 8.4 Demo

`nfi demo` runs the generator (`src/network_flow_insight/demo/generator.py`, re-exported at
`tests/fixtures/generator.py`) with a fixed seed, writes the synthetic estate to a
temp directory, runs the aggregate and all precision tools over DuckDB instead of Athena, and
renders the full report. No credentials. The generator produces, per tier: flow logs in the standard
layout, an inventory JSON (provider C schema), gateway metrics, a CUR extract, a Resolver extract,
and a ground-truth JSON that the evals compare against. `nfi demo-estate DIR` writes the estate (flow logs under
`DIR/s3/AWSLogs/`) so it can be synced to an S3 bucket in a test account and exercised through real Athena.

## 9. IAM

### 9.1 Customer-environment permissions (read-only, both modes)

```
s3:GetObject, s3:ListBucket                       → flow-log bucket and prefix
athena:StartQueryExecution, GetQueryExecution, GetQueryResults, StopQueryExecution, GetWorkGroup
glue:GetDatabase(s), GetTable(s), GetPartition(s)  → the Glue catalog (read)
ec2:DescribeVpcs, DescribeSubnets, DescribeRouteTables, DescribeNetworkInterfaces, DescribeNatGateways,
  DescribeVpcEndpoints, DescribeManagedPrefixLists, DescribeTransitGatewayAttachments
                                                    → provider A (exactly the calls in core/inventory/ec2.py; a test keeps the two
                                                       lists equal; these have no IAM resource type, so Resource "*")
ec2:GetManagedPrefixListEntries                     → provider A, prefix lists in the stack's Region (account open: AWS-managed lists belong to another account)
config:SelectAggregateResourceConfig                → provider B (optional): granted only when an aggregator name is configured, on aggregators in the stack's account and Region
kms:Decrypt                                         → only if a flow-log bucket key ARN is configured
cloudwatch:GetMetricData, ListMetrics               → gateway metrics (optional; Resource "*", see below)
pricing:GetProducts                                 → (no IAM resource type, so Resource "*")
```

The hosted role has no `sts:AssumeRole`. The CUR and Resolver rungs read tables in other accounts through a role the
operator supplies, which only local runs do.

The eight EC2 describe calls, `cloudwatch:GetMetricData`, `cloudwatch:ListMetrics` and `pricing:GetProducts` are the only
customer-environment reads left on `Resource: "*"`, in three separate statements. The eight EC2 calls and
`pricing:GetProducts` have no resource type in AWS's published IAM data. The two CloudWatch actions list a `dataset`
resource type, which AWS documents for OpenTelemetry metrics (one default dataset per Region). Classic metric reads
are not shown to be authorized against it, and a wrong ARN would silently break the gateway-metrics check, so they stay on
`*` until that is verified in a deployment. The shipped tests pin the list of wildcard reads.

### 9.2 Agent-managed resources (write, scoped by ARN)

The hosted execution role's write statements name the agent's own resources by ARN. They carry no tag condition;
the resources are tagged `agent-managed: "true"` for ownership and cost reporting.

```
s3:PutObject, GetObject, ListBucket, DeleteObject  → report bucket / results prefix
kms:Encrypt, Decrypt, GenerateDataKey              → the stack's key
glue:CreateTable, UpdateTable, DeleteTable, CreatePartition, BatchCreatePartition → agent database only
bedrock:InvokeModel, InvokeModelWithResponseStream, ApplyGuardrail
logs:CreateLogGroup, CreateLogStream, PutLogEvents → the runtime's log groups
xray:PutTraceSegments, PutTelemetryRecords          → telemetry (cannot be resource-scoped)
```

The stack creates the agent database and the Athena workgroup, so the hosted role holds no create permission for
them. When the agent runs locally, the opt-in create path (`--create-resources`, `nfi create-table --confirm`) runs
with the caller's own credentials, which then need `glue:CreateDatabase` and `athena:CreateWorkGroup`.

There are no mutating actions on customer resources anywhere in the code, so no
`MUTATING_ACTIONS.md` is needed. Creating the agent's own Glue database, table and workgroup is
agent-internal (the agent creates and owns these resources) and is still gated by explicit opt-in.

## 10. Observability and safety

- Structured JSON logs with, for every Athena query, the execution ID, scanned bytes, elapsed time and row count,
  and error classes for failures; no raw flow records in logs. The report lists the queries it ran. Attribution to a
  caller comes from Athena's query history and AWS CloudTrail.
- X-Ray on the hosted runtime; CloudWatch alarms on error rate and P99 latency. The runtime answers a failed
  invocation with an `error` reply, so the scheduled-run invoker parses the reply and raises on `error` (or a reply
  that is not a JSON object); only then does the Lambda error alarm see a failed run. A reply carrying `agent_error`
  or `fallback` still produced a report and is logged as a warning without failing. The invoker is never retried,
  because a retry would start a second full agent run.
- Guardrails applied in `BedrockModel` config in both modes.
- Prompt injection: tool outputs are data; destination names from Resolver logs and tags from
  inventory are rendered as text, never interpreted as instructions; the system prompt says so.
- Cost: the gauge and ceiling [§7.2]; a per-session Athena budget in config; a per-query bytes-scanned cutoff on the
  hosted workgroup; the run budget [§8.2, requirements §7.11] for model and tool calls; Bedrock prompt caching
  for the system prompt.

## 11. Evaluation

Two layers:

1. **Deterministic tests** (`tests/`): every E-id in [§11] that has byte-exact ground truth (E1–E8,
   E10, E10a, E11, E12, E13, E14) is a pytest against the fixture generator. Precision tools are
   tested to the byte; the agent loop is exercised with a recorded-model harness for parity (E12).
2. **Behavioural evaluation** (Strands Evals; the written report ships as `eval/eval-report.md`): focus
   on `toolcallingaccuracy` (the agent calls precision tools rather than computing in prose), on the
   reconciliation-before-shares rule, and on chat-mode SQL safety (E9). Results scored per requirement
   section.

A release requires all deterministic tests green and the behavioural report present.

## 12. Release surface

Root-level entries beyond the template's `src/`, `infra/`, `tests/`, and why:

| Entry | Classification | Reason |
|---|---|---|
| `skill/` | public | `SKILL.md` is how MCP hosts get the method; customers need it |
| `scripts/` | public | `collect_inventory.py` is the provider C path; customers run it |
| `intent.example.yaml` | public | Documented schema customers copy |
| `Dockerfile` | public | Hosted deployment image |
| `.gitignore` | public | Keeps build output and reports out of forks |
| `pyproject.toml`, `requirements.txt` | public | Install |
| `Makefile` | public | `make demo`, `make test`, `make deploy` |
| `SECURITY.md` | public | Threat model and data classification |
| `eval/eval-report.md` | public | Reliability report: what the behavioural evaluation showed and did not show |

Everything else in the development repository (evaluation scripts, scan records, CI and process files) is
development-only and does not ship.

## 13. Hard boundaries and success criteria

As in `requirements.md` §9 and §10; the design adds no exceptions. The design's own invariants:
every figure comes from §3.2; every Athena statement passes §4.4; the raw table is scanned once per
window; no listening socket in local or MCP mode; no store other than the Parquet aggregate and the
report bucket.
