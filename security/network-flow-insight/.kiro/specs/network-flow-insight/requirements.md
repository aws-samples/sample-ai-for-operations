# network-flow-insight — Requirements

## 1. Purpose

`network-flow-insight` answers a question every AWS customer asks and few can answer with
evidence: **"Where does my data go, and is that what I intended?"**

It reads VPC Flow Logs already delivered to Amazon S3, runs cost-aware Amazon Athena queries
over them, and produces a traffic map of the estate: what leaves to the internet and by which
path, what crosses Regions, how AWS services are reached (NAT gateway, gateway endpoint or
interface endpoint), what moves between VPCs, and what is being rejected. It reconciles its
figures against the gateways' own Amazon CloudWatch metrics (and optionally against billing) so
that every number is measured rather than estimated. It presents the facts with exact figures,
states how confident it can be given the flow-log format and inventory it found, and lays out the
architecture options the evidence supports: egress filtering, central inspection, private
endpoints, Amazon VPC Lattice, routing changes. It does not make those changes.

This is proactive governance and security visibility, not incident investigation. The output is
an evidence pack a platform, network or security team can take into an architecture or risk
discussion, and, once a baseline has been agreed, a drift report against that baseline.

## 2. Who it is for

| Persona | The moment | What they need |
|---|---|---|
| Platform / network engineer | "Show me what left the estate last week, by destination and path, and what crossed Regions." | Run it with the read-only role they already hold; get a report they can put in front of a security forum; ask follow-up questions while the data is fresh. |
| Security / compliance lead | Periodic: "Is egress still what we agreed?" | A drift report against an agreed baseline, produced on a schedule, landing in a known place. |
| Architect | "What share of NAT traffic is AWS-destined and could go private? What would a central egress path have to carry on a peak weekday?" | Interactive questions over the same data, with figures that tie out to the gateways' own metrics. |
| Evaluator (open-source adopter) | "Does this show me anything useful in my account in the next 30 minutes?" | Clone, point it at a bucket, run. Value before any infrastructure is deployed. |

The target audience is any AWS customer with VPC Flow Logs in S3 and Athena available:
regulated telecommunications operators, financial services, security teams and platform
engineering groups. Success is measured by adoption (downloads and use from the public
repository), which is why the evaluator persona shapes the first-run experience.

## 3. Why an agent, and why this shape

### 3.1 What already exists, and where it stops

| Need | Existing capability | Where it stops |
|---|---|---|
| Natural-language questions over flow logs | Amazon Q in QuickSight; Athena generative SQL | Translates words to SQL. Does not know that a gateway-endpoint flow logs on the workload interface with a public destination, that NAT traffic must be scoped to the NAT interface to count once, or that an EC2 public range is not an AWS service. |
| Bytes through each gateway | CloudWatch metrics for NAT gateways, interface endpoints, Transit Gateway attachments | Totals per gateway. No composition: nothing about where the bytes went. |
| Latency, loss, retransmits | Amazon CloudWatch Network Flow Monitor | Performance only. |
| Pod-level inter-AZ and NAT traffic | Amazon EKS Container Network Observability | Amazon EKS only. |
| "Can A reach B?" | VPC Reachability Analyzer, Network Access Analyzer | Reasons from configuration, not observed traffic. |
| Malicious traffic | Amazon GuardDuty | Threats only. Legitimate-but-unintended egress is invisible to it. |
| Data-transfer charges | AWS Cost and Usage Report, AWS Cost Explorer | Totals per resource and usage type. Same-Region traffic to AWS services through NAT carries a processing charge but no destination, so billing cannot say how much NAT traffic was AWS-bound. |
| Incident root cause | AWS DevOps Agent | Reactive. Investigates after a signal. |
| FinOps agent with flow-log add-on | `aws-samples/sample-cost-analyzer-agent` (AgentCore Runtime, Strands, CUR 2.0, optional VPC Flow Log queries) | A billing agent that reaches into flow logs for data-transfer cost drivers. Requires a custom log format; no path classification by interface role, no NAT scoping, no reconciliation, no integrity checks, no intent baseline or drift, no governance framing. |
| Earlier samples | `vpc-flowlogs-for-data-transfer-calculation` (inter-AZ only, Lambda and DynamoDB), Transit Gateway and QuickSight flow-log samples | Narrow, non-agentic, and in most cases several years old. Useful as precedent for individual joins and queries. |

The gap is the standing, evidence-backed answer to "where does my data go, by which path" for
every compute type, working with the flow-log format the customer already has, with the domain
knowledge needed to read flow logs correctly and the reconciliation needed to trust the result.
This agent is a flow-log specialist that reaches into billing; the cost analyzer is a billing
specialist that reaches into flow logs. Both can coexist in the same repository.

### 3.2 Why not an AWS DevOps Agent skill

AWS DevOps Agent has a prevention mode and scheduled custom agents, so "proactive" alone does
not rule it out. Three things do. The audience (security, compliance and platform teams) does
not live in a DevOps Agent Agent Space. The artefact is a reproducible report, not an
investigation thread. And the core of the work is partition-pruned Athena over large tables,
inventory joins and exact arithmetic, which requires a custom tool layer regardless of host. The
tool layer is designed so it can later be exposed to DevOps Agent as an MCP server for the
reactive side (§4.3), so the two never diverge.

### 3.3 Why it needs agentic reasoning

The investigation path changes with what the data shows and with what the customer's flow logs
and inventory can express. The agent must discover which fields exist and which inventory it can
reach, choose a classification strategy accordingly, decide which cuts of the data to pursue
(path, destination bucket, Region, AWS service, account, port, VPC pair, time profile), notice
when a total fails to reconcile and work out why, and explain the result in the customer's own
terms. A fixed set of saved queries cannot do this.

## 4. Scope

### 4.1 In scope (v1)

1. **Capability probe.** Discover the flow-log table, its fields, partitioning and coverage;
   discover which inventory sources are reachable; assign a capability tier (§6); report what the
   tier allows and what would raise it.
2. **Integrity checks.** Before any figure is reported: compare the table's partitions with the
   prefixes actually present under the configured flow-log bucket's `AWSLogs/` layout (this
   bucket only; the agent never enumerates other buckets) and flag accounts, Regions or days the
   table cannot see; report the share of `SKIPDATA` and `NODATA` records; where inventory is
   available, list accounts and VPCs that have gateways but no flow log in the table.
3. **Path classification.** Attribute every flow to a path using, in order of authority:
   - the role of the interface the flow was logged on (NAT gateway, interface endpoint, Transit
     Gateway attachment, load balancer, workload), from inventory;
   - the subnet's route table (default route to NAT gateway or internet gateway; gateway-endpoint
     routes for Amazon S3 and Amazon DynamoDB);
   - the `traffic-path` field where present.
   Path classes: internet via NAT gateway, internet direct via internet gateway, gateway endpoint,
   interface endpoint, Transit Gateway, VPC peering, intra-VPC same-AZ, intra-VPC cross-AZ,
   cross-Region, virtual private gateway or AWS Direct Connect, unknown.
4. **NAT-scoped analysis.** Measure NAT traffic on the NAT gateways' own interfaces. A NAT
   gateway's private address is source or destination on every record its interface logs, on two
   legs: the workload side (workload to and from the NAT address, the real remote carried in
   `pkt-srcaddr`/`pkt-dstaddr`) and the internet side (NAT address to and from the remote). Count
   the internet-side (translated) leg only, so each byte counts once and the other address is the
   remote end. Name the originating workloads from the workload-side (untranslated) leg. Report
   direction (outbound and return) separately.
5. **Destination classification.** Classify remote addresses against the customer's own VPC and
   subnet CIDRs, customer-named networks from the intent file (on-premises ranges, partner ranges,
   SaaS egress ranges), AWS public ranges (`ip-ranges.json`, most-specific service match), managed
   prefix lists, and optionally Route 53 Resolver query logs for naming. Addresses that match only
   the EC2 or AMAZON ranges are "AWS-hosted, unverified", never "AWS service". Private addresses
   outside any known VPC or named network are "private, unnamed". Group the result into
   destination buckets using a default taxonomy or the customer's own (§7.5).
5a. **Conversation pairing and the aggregate.** Run one pass over the raw partitions for the
   window into a compact aggregate (per day, interface, local address, remote network, port,
   protocol, action, direction) written as Parquet to the agent's own results bucket, pair the two
   legs of each exchange into client→server conversations by server-port inference, and run every
   report section and chat question against the aggregate. Raw scan cost is paid once per window,
   not once per section. A stored aggregate is reused by later sessions only if it was built after
   the window settled (the end of its last day plus a configurable delivery margin); a window that
   has not settled, or whose stored aggregate predates settlement, is rebuilt and that build is
   never reused, so late-delivered records are never silently left out. A report over a window
   that has not settled says its totals are provisional and that gateway metrics run ahead of
   the delivered records.
6. **Traffic map ("describe" mode).** The core report, on demand, over a configurable window
   (default the last 7 complete days):
   - coverage and integrity findings (items 1 and 2);
   - volume by path class, with direction;
   - internet egress by destination bucket, AWS service, protocol and port;
   - AWS service traffic by how it was reached, including: interface endpoints that exist but
     whose service traffic still crosses NAT; subnets without gateway-endpoint routes whose S3 or
     DynamoDB traffic crosses NAT; cross-Region S3 or DynamoDB via NAT;
   - inter-VPC and cross-Region traffic;
   - concentration: top accounts, Regions, VPCs and workloads by volume and by share of growth;
   - time profile: per-day series, weekday versus weekend, peak day and peak hour;
   - gateway inventory: NAT gateways with their bytes in the window, including idle or
     near-idle gateways;
   - rejected flows: top sources, destinations and ports;
   - what changed versus the previous equal window;
   - a consumer→provider dependency view: conversations grouped by network group and service
     port, written to the data pack as an edge-list CSV and drawn as a static diagram in the HTML
     report (presentation only; no graph database or other store);
   - reconciliation of flow-derived totals by whichever rungs of the ladder are available (item
     11);
   - architecture options the evidence supports, each tied to the flows that justify it and to
     the published rate for each path in that Region;
   - a methodology and reproducibility appendix (§8).
   The report is layered: a one-page summary, the sections above, appendices, and a data pack
   (CSV and JSON, including the per-day series and the edge list) so readers can build their own
   picture. Volume of data is not the constraint; the aggregate (item 5a) keeps scan cost fixed per
   window and the layering keeps the report readable.
7. **Trend from metrics (when reachable).** Long-range trend (up to 15 months) of bytes through
   NAT gateways, interface endpoints and Transit Gateway attachments from CloudWatch metrics, with
   no Athena scan, for the accounts whose metrics the agent can read (same account, or a
   monitoring account with CloudWatch cross-account observability already configured). Where
   metrics are not reachable, trend comes from flow-log per-day series over the windows the
   customer is willing to scan, and the report says so.
8. **Interactive questions ("chat" mode).** Natural-language questions answered over the same
   data, where the agent composes and runs Athena SQL or metric queries, with the same cost gauge
   and the same rule that every figure comes from code.
9. **Intent baseline, drift and what-if.** `intent draft` generates a baseline from an observed
   window for a human to prune and commit; `drift` compares a new window against the committed
   baseline; `what-if` treats the committed intent as if it were enforced egress policy and
   reports the share of observed traffic that would be denied, by destination bucket and by
   originating workload. If no baseline exists, describe mode is the default and the report says
   so.
10. **Cost gauge.** Estimate scanned bytes and cost before every Athena query, report actuals
    after, keep a running total, and ask for confirmation above a configurable ceiling.
11. **Reconciliation ladder.** Each rung is used when available and the report names the rungs it
    used:
    1. **In-data leg check** (always available): on each NAT interface, bytes on the translated
       (internet-side) leg against everything else on the interface: the untranslated
       (workload-side) leg plus any records that carry no known NAT address. They should agree
       within a small margin. Well below 1 means a NAT address is missing from the filter; well
       above 1 means a non-NAT address is in the filter. Unsolicited inbound to a NAT address
       (internet-side records that match no translated outbound record by remote, remote port and
       protocol) is never translated; it is reported apart and is in no total or comparison.
    2. **Gateway metrics** (when reachable, see item 7): flow-derived totals per gateway against
       CloudWatch metrics for the same window. When the gateway's interfaces logged SKIPDATA
       records in the window, a low ratio names dropped flow-log records as the likely cause,
       whatever share of records SKIPDATA is.
    3. **Cost and Usage Report** (when a payer-side role is supplied): flow-derived totals by
       category against billed usage types for the same window and account set.
    4. **Reference figure** (optional, needs no permission): a billed or otherwise trusted total
       for a day or month that the operator already has and types in, compared with the
       flow-derived figure for the same scope and window.
12. **Demo mode.** A bundled synthetic estate (deterministic generator, standard S3 layout at each
    tier, matching inventory, metrics and CUR extracts) that renders a complete report with no AWS
    data, so an evaluator sees the output before connecting anything. The same generator produces
    the fixtures for §11.
13. **Deployment modes.** (a) Hosted on Amazon Bedrock AgentCore Runtime in the account that
    owns the flow-log bucket, with a scheduled report mode; (b) run locally by an operator with
    their own read-only credentials to that account. Same code, same tools, same reports.
14. **Portable surfaces.** A Model Context Protocol (MCP) server over the same tools for use from
    MCP-capable assistants (Kiro CLI, Claude Code, Codex, Cursor, Amazon Q Developer and others),
    and a `SKILL.md` carrying the investigation method in the open Agent Skills format.
15. **Table creation (opt-in).** Where no table exists, create one in an agent-managed AWS Glue
    database using partition projection over the standard `AWSLogs/<account>/vpcflowlogs/<region>/
    <yyyy>/<mm>/<dd>/` layout (and the Hive-compatible variant), with the account enumeration
    discovered by listing the bucket, plus a dedicated Athena workgroup and results bucket.

### 4.2 Out of scope

- Security-group or NACL rule tightening or rule-level analysis.
- Network performance (latency, loss, retransmits).
- Incident investigation and root-cause analysis.
- Any change to customer network configuration. The agent recommends; humans act.
- Threat detection. Rejected flows are described, not judged as attacks.
- Proving completeness of traffic capture. Flow logs have known blind spots (§8.3); the report
  states them and the agent never claims to have seen everything.

### 4.3 Deferred to a later version (v2)

- Hosting the MCP server behind a signed endpoint for AWS DevOps Agent to use during incidents.
- Intent sourced from live prefix lists, tags or a policy service rather than a file.
- AWS Transit Gateway Flow Logs as an additional source.
- Inventory by role fan-out across member accounts where no AWS Config aggregator exists.
- Persisting interface inventory snapshots so that interfaces deleted since the window can still
  be attributed.

## 5. Data sources and access

### 5.1 Hard requirements and optional enrichments

The agent runs with exactly five things: VPC Flow Logs in an S3 bucket, Amazon Athena, an AWS
Glue table over the bucket (existing, or created by the agent on opt-in), read-only credentials to
the account that owns the bucket, and a model (Amazon Bedrock in the packaged agent; the host's
own model when driven over MCP). Nothing else is required.

Everything else in this section is an optional enrichment. Each one, when absent, degrades a
specific capability and the report says so; none of them blocks a run. The agent never requires
the operator to produce anything beyond credentials and a bucket name.

| Enrichment | What it adds | When absent |
|---|---|---|
| Network inventory (any provider A to C) | Authoritative path classification, NAT attribution to workloads, resource names | Forwarding interfaces detected from the data and labelled inferred; destinations classified by CIDR only |
| Gateway metrics | Reconciliation rung 2; long-range trend without scanning | Reconciliation by leg check and, if offered, a reference figure; trend from scanned per-day series |
| Cost and Usage Report access | Reconciliation rung 3 | Omitted, with the rung named as unavailable |
| Reference figure typed in by the operator | Reconciliation rung 4 | Omitted |
| Route 53 Resolver query logs | Names for destinations that match only generic AWS ranges or SaaS | Such destinations stay as "AWS-hosted, unverified" or "other internet" |
| Intent file | Drift, what-if, customer-named networks and buckets | Describe mode with the default taxonomy; the agent offers to draft one |

### 5.2 Sources

| Source | Required? | Access | Notes |
|---|---|---|---|
| VPC Flow Logs in S3, queried through Athena | Yes | `s3:GetObject`, `s3:ListBucket` on the log bucket; Athena read-side query actions; `glue:Get*` | Text or Parquet; default or custom format; date-partitioned, ideally by account and Region as well. |
| Glue table and Athena workgroup | Preferred existing | `glue:Get*`, `athena:GetWorkGroup` | If absent, see §4.1(15). The only write action in the product; explicit opt-in; created resources tagged `agent-managed: "true"`. |
| Network inventory, provider A: same-account Amazon EC2 | One inventory provider is strongly preferred | `ec2:Describe*` (VPCs, subnets, route tables, network interfaces, NAT gateways, VPC endpoints, Transit Gateway attachments, managed prefix lists) and `ec2:GetManagedPrefixListEntries` (not covered by `ec2:Describe*`; hosted, limited to prefix lists in the deployment Region with the account left open because AWS-managed lists belong to another account) | Covers the account the agent runs in. Sufficient for the evaluator and single-account estates. |
| Network inventory, provider B: AWS Config aggregator | Optional | `config:SelectAggregateResourceConfig` | Only usable when an aggregator covering the logged accounts is reachable from where the agent runs. In many estates the aggregator lives in a separate audit account, so this cannot be assumed. The hosted deployment grants the action only when the operator names an aggregator in the deployment account and Region, and then only on aggregators there; with no name it grants no AWS Config action. |
| Network inventory, provider C: inventory file | Optional | None (a file the operator points the agent at) | A read-only collection script ships with the agent (the same `describe-*` calls as provider A, emitted in a documented JSON schema). A platform team can run it through whatever already reaches their accounts and hand the agent the output. It is an offer, not a prerequisite. |
| Network inventory, provider D: none | Default fallback | None | Flow-log-only heuristics: a NAT gateway interface has its own private address on nearly every record, talking to public remotes on one leg and to private workloads on the other with the bytes of the two legs in balance, port for port (`pkt-*` fields showing the real remote on the workload leg raise confidence); a Transit Gateway attachment also has its own address on every record but `pkt-*` names the real peer on its side; any other interface that logs records in which neither address is its own is a forwarding interface. Without `pkt-*` fields, a Transit Gateway attachment is recognised when the workloads it talks to are themselves logged: they record the real peer, never the attachment's address; otherwise it cannot be told from a workload. Reported as inferred, with the one command that would confirm it. |
| Gateway metrics | Optional | `cloudwatch:GetMetricData`, `cloudwatch:ListMetrics` in the account the agent runs in | Metrics exist only in the account that owns the gateway, so this normally covers that one account. If the customer has already made the agent's account a CloudWatch monitoring account (cross-account observability), the same call also returns source-account metrics; the agent adds no plumbing for this and never assumes into other accounts to collect metrics. |
| Reference figure | Optional | None (a number the operator types in, with its scope and window) | For example the billed NAT gigabytes for a day, taken from Cost Explorer or the invoice. Compared with the agent's figure for the same scope and window. |
| AWS public IP ranges (`ip-ranges.json`) | Yes | Public download over HTTPS | Most-specific service match. |
| Published prices | Yes | `pricing:GetProducts` | NAT processing, interface endpoint processing, Regional and inter-Region transfer, data transfer out, per Region. Used as context for options; never hard-coded. |
| Route 53 Resolver query logs via Athena | Optional | Same Athena/Glue/S3 reads | Names destinations that match only generic AWS ranges or belong to SaaS providers. |
| Cost and Usage Report via Athena | Optional | Same Athena/Glue/S3 reads, often through an assumed role in another account | Second rung of the reconciliation ladder. |

The agent runs with the credentials it is given. Locally, that is the operator's own role. Hosted,
it is the AgentCore Runtime execution role, scoped to the resources above. In local runs, where the Cost and
Usage Report or the Resolver query logs live in another account, the customer creates a read-only role with a trust
policy to the agent and supplies its ARN in the agent's settings; `sts:AssumeRole` into that role is the only
cross-account action. The hosted deployment does not run those two rungs: its role has no `sts:AssumeRole` and the stack
takes no role ARN.

Every customer-environment permission is read-only. The agent-managed Glue database, workgroup,
results bucket and report bucket are the only resources it may write to.

## 6. Capability tiers

Confidence depends on two things: the fields in the flow log, and which inventory provider (§5,
A to D) is available. The probe assigns a tier and every report states it together with the
provider used.

| Tier | Requires | Authoritative | Inferred or unavailable |
|---|---|---|---|
| **Basic, no inventory** | Default (v2) fields only; provider D | Volumes, ports, protocols, accept/reject, per-account and per-Region totals (from partitions); forwarding interfaces detected from the data | Which interface is a NAT gateway (inferred from its balanced two-leg traffic), and the workloads behind it (from its workload-side leg); gateway-endpoint traffic indistinguishable from NAT without route tables; AWS service naming by CIDR match only |
| **Basic with inventory** | Default (v2) fields plus provider A, B or C | Path class for every flow logged on a NAT gateway, interface endpoint, Transit Gateway or load balancer interface; NAT traffic counted once (internet-side leg) and attributed to workloads from the workload-side leg; gateway-endpoint and IGW-direct paths from route tables; direction on NAT paths; AZ from interface inventory | Attribution for interfaces deleted since the window (or absent from a provider-C snapshot); original addresses behind NAT or Transit Gateway; AWS service naming by CIDR match only |
| **Enhanced** | Basic with inventory plus `vpc-id`, `subnet-id`, `az-id`, `flow-direction`, `pkt-srcaddr`, `pkt-dstaddr` | Everything above without depending on inventory age (an interface deleted since the window is classified from the subnet its records carry); original addresses behind NAT and Transit Gateway; direction for all flows | AWS service naming still by CIDR match |
| **Full** | Enhanced plus `traffic-path`, `pkt-src-aws-service`, `pkt-dst-aws-service`, `region` | Path class and AWS service name from the record itself; inventory becomes a cross-check rather than a dependency | Nothing material for this product's scope |

When the tier is below Full, the report includes a specific recommendation: the custom flow-log
format string to enable, the delivery options to set when the flow log is next recreated
(Parquet, Hive-compatible prefixes, hourly partitions) with the expected effect on scan cost, and
which report sections would gain confidence.

## 7. Behaviour requirements

Written as "when … the agent shall …" so each can be tested.

### 7.1 Probe and integrity
- When started against a configured table, the agent shall read the schema, partitioning scheme
  (projection or enumerated partitions) and partition coverage, assign a capability tier, name the
  inventory provider it will use, and state all of this before running any analysis query.
- When the table's partitions do not cover prefixes present in S3 for the window, the agent shall
  list the missing accounts, Regions or days and shall exclude them from totals with a visible
  caution rather than silently under-count.
- When `SKIPDATA` or `NODATA` records exceed a configurable share of the window, the report
  shall carry a caution on affected totals.
- When inventory shows gateways in accounts or VPCs that have no flow log in the table, the
  report shall list them as uncovered.
- When no inventory provider is configured, the agent shall say which provider options exist,
  offer the provider-C collection script, and proceed at "Basic, no inventory" tier with every
  inferred classification labelled as such.
- When no table is configured, the agent shall look for existing flow-log tables in the Glue
  catalog and offer them; only if none exist shall it offer to create one, and only with explicit
  confirmation.

### 7.2 Cost gauge
- Before each Athena query the agent shall estimate bytes to be scanned from the size of S3
  objects under the partitions the query will touch, and show the estimate in GB and in currency
  at the Region's Athena rate.
- After each query the agent shall report actual bytes scanned and the running total for the
  session or report.
- When an estimate exceeds the configured ceiling, the agent shall ask for confirmation before
  running in interactive modes, and shall skip the query and record the skip in scheduled mode.
- Every Athena query shall carry partition predicates; a query without them is a defect. A query on the raw
  flow-log table shall carry a literal start and end date that lie inside the window its estimate covers; one that
  cannot show that bound is rejected and never run, so the scan cannot exceed the estimate.
- When a question can be answered from CloudWatch metrics, the agent shall prefer metrics over
  flow-log scans and say so.
- The hosted deployment shall set a bytes-scanned cutoff per query on the agent's Athena workgroup, so that a query the
  gauge mis-estimated is stopped by Athena itself. The default is the scan a 5 USD ceiling allows (1 TB, decimal) and the
  deployer can change it.

### 7.3 Classification and NAT scoping
- The agent shall classify each flow's path by interface role first, route table second, and
  `traffic-path` where present, and shall record which method classified each path class. Where a
  record's own `traffic-path` contradicts the classification from current route tables, the agent
  shall report those flows (subnet, both classes, bytes) with a caution that routes changed during
  the window or the inventory is not from the window.
- When measuring NAT traffic, the agent shall query the NAT gateways' interfaces using all of each
  gateway's private addresses (including secondary addresses) and shall count only the translated
  leg: records where a NAT address is source or destination and the packet's own address on the NAT
  side is the NAT address (`pkt-srcaddr` outbound, `pkt-dstaddr` on return), or, without `pkt-*`
  fields, where the other address is not private. It shall report outbound and return bytes
  separately, records on a NAT interface with no known NAT address as unmatched, and inbound records
  that match no translated outbound record (by remote, remote port and protocol) as unsolicited, kept
  out of the translated leg.
- When an interface's records are not in the inventory (deleted since the window), the agent shall
  classify them from the subnet the record carries where the format has `subnet-id`, and shall count
  their outbound bytes and their inbound bytes from public sources.
- The agent shall count each byte once: inbound from another workload is left to that workload's
  outbound records only if that workload's interface has records in the data; when it has none (its
  VPC's flow log is not in the table), the inbound bytes are counted where they arrive.
- The agent shall always run the in-data leg check (§4.1(11), rung 1) on NAT-scoped totals and,
  where reachable, compare them with the NAT gateways' CloudWatch metrics for the same window.
  When a gateway-metrics or billing ratio is near 2, it shall report that both legs are still
  included; when well above 1, that non-NAT traffic has leaked into the filter; when well below 1,
  that coverage is incomplete.
  It shall not present NAT composition shares until the total reconciles within the configured
  tolerance on at least one rung, or shall present them with an explicit caution.
- The agent shall pair flow legs into client→server conversations by server-port inference and
  shall label conversations where the inference is ambiguous (both ports ephemeral, or both
  well-known).
- When classifying a remote address, the agent shall use the most specific match in
  `ip-ranges.json`. Addresses matching only EC2 or AMAZON ranges shall be bucketed as
  "AWS-hosted, unverified", never as an AWS service. Where Resolver query logs are available the
  agent shall use them to name such destinations.
- When an interface endpoint for a service exists in a VPC and that service's prefixes still
  appear on the VPC's NAT path, the report shall name the endpoint, the volume still crossing
  NAT, and the likely causes (private DNS disabled, subnets outside the endpoint's AZs, cross-
  Region targets).
- When a subnet's route table lacks a gateway-endpoint route and that subnet's S3 or DynamoDB
  traffic appears on the NAT path, the report shall name the subnet and the volume.

### 7.4 Describe mode
- When asked for a traffic map with no window given, the agent shall use the last 7 complete
  days.
- The agent shall produce every section in §4.1(6) that the tier allows, and for sections it
  cannot produce, say why and what would enable them.
- Every figure (bytes, flows, percentages, counts, rankings, deltas, growth shares, peaks, costs)
  shall come from a precision tool, never from the model.
- All byte figures shall be computed in bytes and reported in decimal units (GB, TB), labelled.
  Where a figure is compared with a billed or payload-based figure, the report shall state the
  known differences (IP headers in flow bytes; protocol framing between payload and wire).
- The options section shall tie each option to the flows that justify it and to the published
  rate for each path in that Region (for example: volume of S3 traffic crossing NAT in the window,
  the NAT processing rate, the gateway-endpoint rate of zero), and shall not present any single
  option as the answer.

### 7.5 Destination buckets and intent
- The agent shall ship a default destination taxonomy (customer networks; AWS services by name;
  AWS-hosted unverified; known SaaS and CDN ranges where identifiable; other internet) and shall
  accept a customer-defined taxonomy in the intent file that maps classification results to the
  customer's own buckets and the expected disposition of each (for example: not subject to
  inspection; candidate for a private path; must traverse inspection).
- When asked to draft intent, the agent shall produce a baseline file in the documented schema
  from the observed window, with the evidence for each entry (volume, flow count, first and last
  seen, path) so a human can prune it.
- The intent file shall also carry customer-named networks (name, kind, CIDR list) used by
  destination classification (§4.1(5)).
- When a committed baseline exists and drift is requested, the agent shall report matched
  entries, traffic not covered by any entry, entries with no traffic in the window, and traffic
  whose path differs from the baseline's expected disposition. It shall not modify the baseline.
- When what-if is requested against a committed baseline, the agent shall report the share of
  observed bytes and conversations that fall outside the baseline, by destination bucket and by
  originating workload, as the impact of enforcing the baseline as policy.
- When no baseline exists, the agent shall default to describe mode and say that a baseline can
  be drafted from this run.

### 7.6 Reconciliation
- The agent shall use every rung of the ladder (§4.1(11)) that is available and shall name, in
  the report, which rungs were used and which were not and why.
- For every gateway type whose metrics are reachable (NAT gateway, interface endpoint, Transit
  Gateway attachment), the agent shall compare flow-derived bytes with CloudWatch metrics for the
  same window and report the ratio per gateway and in aggregate.
- When the operator supplies a reference total, the agent shall compare it with the matching
  flow-derived figure for the same scope and window and report the ratio.
- When CUR access is configured, the agent shall additionally compare flow-derived totals by
  category with the billed usage types for the same window and account set, and shall state the
  account set used, since a mismatch in account coverage is the commonest cause of a gap.
- When any reconciliation differs by more than the configured tolerance, the report shall carry a
  visible caution on the affected figures and the agent's best explanation of the gap.

### 7.7 Chat mode
- When asked a question the agent can answer from the data, it shall compose SQL or metric
  queries constrained to the window and partitions, run them through the cost gauge, and answer
  with figures from code and the query it used.
- When asked a question outside the data (performance, intent it has not been given, events it
  cannot see) it shall say so rather than infer, and when it declines it shall give the reason in its own
  words rather than a bare "blocked" message.
- Every chat answer shall be checked after it is written for figures that no tool returned and the user
  did not type. If there are any, the answer carries a visible caution naming them and the hosted response
  lists them. The model does not do arithmetic: derived figures come from the precision tools.

### 7.8 Reports and reproducibility
- Every report shall carry: window, tier, inventory provider, tables and workgroup used, total
  bytes scanned and cost, reconciliation results, and for every figure the SQL statement or
  metric query and the Athena query execution ID that produced it.
- Reports shall be written as Markdown (and optionally HTML) to a local path in local mode and
  to the agent's own S3 bucket in hosted mode. Per-day series shall also be available as CSV.
- Reports shall not contain raw flow records. They contain aggregates, named resources and
  classified destinations.

### 7.9 Deployment and scheduling
- The same package shall run locally (CLI) and on Amazon Bedrock AgentCore Runtime without code
  changes beyond the runtime wrapper.
- In hosted mode, a schedule (Amazon EventBridge Scheduler) shall be able to trigger describe
  or drift mode and deliver the report to S3, with an optional notification.
- A scheduled run that fails shall raise the failure alarm. A run the runtime reports as failed (an `error` reply)
  counts as a failure even though the call itself succeeded, and a failed scheduled run shall not be retried
  automatically, because a retry would start a second full run. A run that produced a report but lost the model
  interpretation (`agent_error`, `fallback`) is logged as degraded and does not raise the alarm.
- Amazon Bedrock Guardrails shall be applied to the model in both modes.

### 7.10 Portable surfaces
- The MCP server shall expose the tool layer over stdio with no model and no agent loop of its
  own, so any MCP host can drive it with its own model.
- The `SKILL.md` shall carry the investigation method (probe and integrity first, tier, NAT
  scoping, reconcile before sharing, cost gauge, figures from code, state blind spots) so MCP
  hosts behave consistently with the packaged agent.

### 7.11 Run limits
- One agent invocation (a scheduled run, or one chat turn) shall be bounded by a number of tool calls and by wall-clock
  time, both configurable, so that an unattended run cannot loop without limit. Defaults: 60 tool calls, well above what
  a normal describe or drift run needs, and 780 seconds, below the 880 second wait of the scheduled-run Lambda. Zero
  disables a limit. Each invocation starts a fresh budget.
- When a limit is reached the agent shall stop using tools and answer from what it already has, saying what is missing. If
  the model keeps asking for tools, or a model call would start well after the deadline, the invocation shall stop with an
  error. A scheduled run that stops this way shall still produce its report from the findings, without interpretation.
- The hosted deployment shall let the deployer set both limits and shall refuse a deadline that the scheduled-run
  Lambda's wait cannot outlast.

## 8. Audit posture

### 8.1 What the output is
An evidence pack: reproducible figures from stored queries over a stated window, reconciled to
the gateways' own metrics, with a stated confidence tier. It supports a governance or audit
conversation. It is not an attestation and does not claim completeness.

### 8.2 What makes it defensible
Figures only from code; every figure traceable to a query and execution ID; reconciliation to an
independent measurement (CloudWatch metrics, and billing where enabled); explicit tier and
inventory provider; explicit integrity findings; explicit blind-spot list; no raw records in the
report.

### 8.3 Known blind spots the report must state
VPC Flow Logs do not capture: traffic to the Amazon DNS resolver; instance metadata; Amazon Time
Sync; DHCP; Windows licence activation; traffic to the VPC router reserved address; some traffic
between endpoint interfaces and Network Load Balancer interfaces; logs vended directly by AWS
services to their destinations. Records are aggregated over the capture window (1 or 10 minutes)
and are not real-time. `SKIPDATA` records mean the capture dropped data. Interfaces without a
flow log attached, and partitions the table cannot see, are invisible. Interfaces deleted since
the window cannot be attributed below Enhanced tier. Gateway endpoints have no interface, so
their traffic is inferred from route tables. Byte counts include IP headers and differ from
payload-based billing by protocol framing.

## 9. Hard boundaries

1. The agent never modifies customer network configuration, security groups, routes, endpoints,
   flow-log settings or any resource it did not create.
2. Customer-environment permissions are read-only. The only write actions are to agent-managed
   resources and only after explicit opt-in.
3. Every number in any output comes from a precision tool. The model never counts, sums,
   averages or compares values in prose.
4. Every Athena query carries partition predicates and passes the cost gauge; a raw-table query is bounded to the
   window its estimate covers.
5. NAT composition shares are never presented without the reconciliation result alongside them.
6. Reports never include raw flow records or any personal data beyond internal IP addresses and
   resource identifiers the customer already holds.
7. The agent never claims completeness and always states tier, inventory provider and blind spots.
8. Nothing in the published artefact identifies any customer, account, person or internal system.
   Fixtures use the documentation account range (`123456789012` and neighbours) and invented
   names.
9. The published artefact is sample code, not a production-ready product, and its README says so in its first screen:
   it is for evaluation and extension, it is not a supported product, and the reader should review the code and its IAM
   permissions, try it in a non-production account and add their own controls before relying on it. It also tells the
   reader to work with their security and legal teams to meet their organizational security, regulatory and compliance
   requirements before deployment, because the aggregates keep full-precision addresses that some jurisdictions treat
   as personal data.

## 10. Success criteria

| Criterion | Measure |
|---|---|
| First-run value | Demo mode renders a full report in under 5 minutes from clone with no AWS access. An evaluator with an existing flow-log table and same-account inventory reaches a complete describe-mode report on their own data in under 30 minutes, with no infrastructure deployed. |
| Scan cost is fixed per window | A full describe-mode report performs one raw scan per window (plus the probe); every section and every subsequent chat question in the session runs against the aggregate. The previous-window comparison is a second window with its own scan; it is optional and is skipped when the cost gauge declines it. |
| Correctness | On a synthetic flow-log fixture with known composition, every reported figure matches the fixture to the byte. |
| Reconciliation | On the fixture, NAT-scoped flow totals match the synthetic gateway metrics within tolerance; the agent detects a planted double-count and a planted coverage gap and reports each correctly. |
| Tier handling | The same fixture at each tier produces reports whose sections, methods and stated confidence differ exactly as §6 describes. |
| Cost transparency | Every Athena query in every mode shows estimate before and actual after; no query runs without partition predicates; trend questions are answered from metrics without a scan. |
| Reproducibility | A reviewer can re-run any figure's stored query and obtain the same value. |
| Adoption | Downloads and use from the public repository; issues and contributions from outside the originating team. |

## 11. Evaluation

The solution is complete for v1 when these evaluations pass. They are specified here so they can be
implemented as tests and used as a release gate. All run against synthetic fixtures committed with the repository (flow logs in the standard S3 layout at each
tier, a matching inventory snapshot, matching gateway metrics, and a matching CUR extract), so
they need no customer data and run in CI.

| ID | Evaluation | Pass condition |
|---|---|---|
| E1 | Probe assigns the right tier on fixtures for each tier, with and without inventory. | Tier, inventory provider and the list of unavailable sections match expectations exactly. |
| E2 | Integrity. Fixture with one account's partitions missing from the table and a planted `SKIPDATA` share. | Missing account listed and excluded with caution; `SKIPDATA` caution present with the computed share. |
| E3 | NAT scoping. Fixture with gateway-endpoint S3 traffic, NAT traffic on both legs in the record shapes a real NAT gateway interface logs (the NAT address on every record), and a NAT gateway with two private addresses. | NAT-scoped total passes the in-data leg check and equals synthetic NAT metrics within tolerance; gateway-endpoint bytes excluded; both addresses honoured; direction split matches ground truth. |
| E4 | Reconciliation diagnostics. Fixtures engineered to produce ratios near 2, well above 1, and well below 1, run with metrics reachable and with metrics absent (leg check and operator reference only). | Each produces the correct diagnosis on every available rung; the report names the rungs used; no composition share is shown without its caution. |
| E4a | Inventory providers. The same fixture run with provider A, provider C (file from the shipped script), and provider D. | A and C yield identical path classification; D detects the forwarding interfaces, labels NAT as inferred, and reports the lower tier. |
| E4b | Conversation pairing. Fixture with known client→server exchanges, including ambiguous port pairs. | Paired conversations match ground truth; ambiguous pairs are labelled, not guessed. |
| E5 | Classification. Remote addresses in S3, DynamoDB, EC2-only and AMAZON-only ranges, plus a customer CIDR and a public address outside AWS. | Most-specific match applied; EC2-only and AMAZON-only land in "AWS-hosted, unverified"; with the Resolver fixture, the AMAZON-only address is named. |
| E6 | Endpoint effectiveness. Fixture with an interface endpoint whose service traffic still crosses NAT, and a subnet lacking a gateway-endpoint route. | Both findings reported with the right volumes and resources. |
| E7 | Describe mode on the Full fixture. | Every section present; every figure equals ground truth; time profile and concentration figures correct; options each cite justifying flows and a rate from the pricing fixture. |
| E8 | Cost gauge. | For ten varied queries, estimate before, actual after, running total correct; a query over the ceiling prompts or is skipped and recorded; no generated SQL lacks partition predicates; a trend question is answered from metrics with zero scan. |
| E9 | Chat mode. | Ten representative questions produce partition-bounded SQL and figures matching ground truth; two out-of-scope questions are declined with the reason. |
| E10 | Intent lifecycle. | Draft from window A validates against the schema with evidence per entry and includes named networks; drift on window B reports the planted new destination, the planted stale entry, the planted path change, and all matches; what-if on window B reports the planted out-of-policy share by bucket and workload to the byte. |
| E10a | Demo mode. | `--demo` renders a complete layered report and data pack from the bundled synthetic estate with no AWS credentials, and the figures match the generator's ground truth. |
| E11 | CUR reconciliation. | With a matching synthetic CUR, agreement within tolerance; with a CUR covering fewer accounts, the account-set mismatch is identified. |
| E12 | Parity. | Local CLI, AgentCore Runtime and MCP-driven runs over the same fixture produce the same figures. |
| E13 | Boundaries. | Static check: IAM policies contain no customer-environment write actions; reports contain no raw flow rows; the model's outputs contain no numbers absent from tool results. |
| E14 | Anonymity. | The public bundle contains no customer names, real account IDs or internal identifiers. |

## 12. Assumptions to validate

- A 7-day default window is useful and affordable at large-estate scale; validate scan cost on
  the pilot estate and set the default ceiling from it.
- Most target customers centralise flow logs in one bucket in the standard `AWSLogs/` layout.
  Inventory for the logged accounts is usually not reachable from that account, so large estates
  will often run at "Basic, no inventory" on first use. The heuristics (provider D) therefore have
  to be good, and the value of supplying an inventory file (provider C) has to be visible in the
  report so the platform team can decide whether it is worth the effort.
- CloudWatch cross-account observability is the exception, not the norm. The in-data leg check is
  expected to be the common reconciliation rung for large estates; metrics, CUR and a typed-in
  reference figure are bonuses where access or a number exists.
- Glue tables and Athena workgroups already exist for most mature customers; the projection-based
  create path serves evaluators and smaller estates.
- The CUR, where present, is usually in a different account from the flow-log bucket and needs
  its own role.
