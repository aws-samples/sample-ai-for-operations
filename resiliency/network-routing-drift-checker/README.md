# Network Routing Drift Checker

A read-only daily check that your AWS Cloud WAN, AWS Transit Gateway and AWS Direct Connect routing still matches the network you designed. Each morning it publishes one message to an Amazon SNS topic: either a one-line "no drift" heartbeat or a drift report listing what changed.

> **Status: prototype.** This is sample code, for non-production usage. You should work with your
> security and legal teams to meet your organizational security, regulatory and compliance
> requirements before deployment. All six checks are in this build. Four need no configuration;
> three more checks run once you upload a short [intent file](#the-intent-file). Optionally, new
> findings are handed to [AWS DevOps Agent](#optional-investigation-with-aws-devops-agent), which
> finds the change behind them and ranks them.

## What it checks

| Check | AWS Cloud WAN | AWS Transit Gateway | Needs configuration? |
|---|---|---|---|
| Attachment in the wrong routing domain | Segment differs from what the core network policy's attachment rules assign | Attachment's `Environment` tag differs from its associated route table's tag | No |
| Prefix leak between domains | A segment sees routes from a segment the policy doesn't share with it (shares, `deny-filter` / `allow-filter`, `create-route` statics and `isolate-attachments` are honored) | A route table sees routes the `tgw_isolation` matrix doesn't allow | No (Cloud WAN); intent file (TGW) |
| Blackhole routes | Any `BLACKHOLE` route | Any `blackhole` route | No |
| Route / prefix counts near a limit | Routes per core network; prefixes advertised to on-premises per DX gateway attachment | Routes per transit gateway; allowed prefixes per DX gateway association; routes received from on-premises per transit VIF (approximate) | No |
| Direct Connect redundancy | A declared VIF pair has a member missing or down, a BGP session down, or both members down | Same | Intent file |
| Hybrid path intent | A prefix is missing, leaves through the wrong Region, isn't using its preferred path, or its backup is down | Same | Intent file |

The decision whether something is drift is deterministic code. The only AI involved is the optional AWS DevOps Agent investigation, and it explains findings that code has already decided; it never decides what is drift.

## How it works

```
Amazon EventBridge Scheduler (daily, your timezone)
  └─► AWS Step Functions
        Init        discover Regions, read the intent file, write a run manifest
        Collect     Cloud WAN once, then each Region in parallel (read-only calls)
                    a Region that fails is reported "not evaluated"; the run continues
        Evaluate    deterministic checks → findings
        Diff        NEW / KNOWN / RESOLVED against yesterday (Amazon DynamoDB)
        Investigate (optional, only for NEW findings) signed webhook → AWS DevOps Agent;
                    the result comes back as an EventBridge event, no inbound endpoint
        Report      heartbeat or drift report → Amazon SNS
Amazon CloudWatch alarms (failed run, missed run, …) → the same SNS topic
```

Regions are discovered automatically: every enabled Region with a transit gateway, the Cloud WAN edge locations, the Region of each Direct Connect gateway association, and the Region of every VIF your intent file names. You can pin or exclude Regions with parameters or in the intent file.

## Prerequisites

- An AWS account that owns the Cloud WAN core network and/or transit gateways and Direct Connect gateways to check. This version is **single-account**.
- Credentials that can deploy a CDK stack (IAM roles, AWS Lambda, Step Functions, DynamoDB, Amazon S3, SNS, AWS KMS, EventBridge Scheduler, CloudWatch).
- Python 3.12+, Node.js 20+, and the AWS CLI v2.
- For the TGW wrong-route-table check: an `Environment` tag (or the tag key you configure) on your **TGW route tables and attachments**. See [Tag convention](#tag-convention-transit-gateway).

- Optional: an AWS DevOps Agent Agent Space for the investigation. See [Optional: investigation with AWS DevOps Agent](#optional-investigation-with-aws-devops-agent).

**Network Manager endpoint.** Cloud WAN is read through AWS Network Manager, a global service with a single endpoint in **us-west-2**. The checker calls it there regardless of which Region you deploy to, so those read-only API calls go to us-west-2.

## Deploy

```bash
cp deploy.env.example .deploy.env      # set SCHEDULE_TIMEZONE (required) and optionally NOTIFICATION_EMAIL
export AWS_PROFILE=<profile> AWS_REGION=<region>
scripts/deploy.sh                      # creates .venv, bootstraps CDK if needed, deploys
```

`ScheduleTimezone` has no default on purpose: CloudFormation refuses to create the stack without it, so the run time never shifts silently with daylight saving. If you set `NOTIFICATION_EMAIL`, confirm the subscription e-mail from SNS. Any other subscriber (chat integration, queue, ticketing bridge) can be added to the `ReportTopicArn` output.

Then check the deployment:

```bash
scripts/smoke-test.sh [region]         # runs once for one Region and checks the report was published
```

Main parameters (all in `deploy.env.example`):

| Parameter | Default | Meaning |
|---|---|---|
| `SCHEDULE_TIMEZONE` | *required* | IANA name, e.g. `Europe/Berlin` |
| `SCHEDULE_EXPRESSION` | `cron(0 5 * * ? *)` | When the daily run starts |
| `REGION_ALLOWLIST` / `REGION_EXCLUDE_LIST` | empty | Comma-separated Regions; a non-empty allowlist replaces discovery |
| `ENVIRONMENT_TAG_KEY` | `Environment` | Tag key for the TGW convention |
| `LIMIT_THRESHOLD_PERCENT` | `80` | When the limit check reports |
| `LOG_RETENTION_DAYS` | `90` | CloudWatch Logs retention |

## Run it on demand

```bash
aws stepfunctions start-execution --state-machine-arn <StateMachineArn output> \
  --input '{"regions": ["eu-central-1"], "lookback_from": "2026-05-01T00:00:00Z"}'
```

Both input keys are optional; `{}` runs the full daily scope. A run with overrides is **partial**: it reports normally but never moves the "last complete run" marker that the daily run uses.

## Reading the report

**Clean day.** One line, for example:

```
Network routing drift check 2026-05-12: no drift. 4 of 6 checks run, 152 resources evaluated, 3 checks skipped (intent file absent).
```

With a valid intent file uploaded it reads `6 of 6 checks run` and has no "skipped" part.

If anything could not be checked (a Region, Cloud WAN, the Direct Connect gateway list, a route table that returned an incomplete list, the intent file), the subject says `(N not verified)` and each item is listed. A partial check never reads as clean.

**Drift.** Counts first, then each finding:

- **NEW**: first seen today.
- **KNOWN**: still present, with first-seen date and age in days. "changed since last run" means details changed; "not re-verified" means its Region or Cloud WAN could not be checked today.
- **RESOLVED**: present last time, gone now (only if its source was checked today).

Each finding has a stable ID (`f-…`), so the same drift keeps the same ID every day. Informational items, such as untagged TGW attachments, are counted separately and are not drift. Every run's full findings are kept for 30 days in the stack's bucket under `runs/<run-id>/findings.json`.

**Investigated drift** (hand-off enabled, subject ends with `(investigated)`). An INVESTIGATION section comes first. Each incident groups related findings and shows: confidence (`high` = a matching change event, `medium` = circumstantial, `low` = no evidence), blast-radius score and counts, how long it's been present, the member finding IDs, the root-cause hypothesis, whether the person or service that made the change was identified, the cited evidence (CloudTrail event, AWS Health event, observed state), read-only commands to verify it yourself, and the link to the investigation. Incidents are ordered by a score the checker computes from the counts, with production-tagged domains weighted highest. The full NEW list follows, so no detail is lost.

If investigation failed for some or all findings, the subject says `(partly investigated)` or `(investigation failed)` and the report names each failed batch and the reason. The raw findings are always in the NEW list.

**Run failed or never started.** The run publishes nothing, and a CloudWatch alarm posts to the same topic instead. Silence never means "fine."

## Tag convention (Transit Gateway)

Tag each TGW route table and each attachment with `Environment=<domain>` (case and surrounding spaces are ignored). An attachment is in the right domain when its tag equals the tag of the route table it is **associated** with.

- Untagged attachment → informational "untagged-attachment" (not drift, never counted as clean).
- Untagged route table → one informational "untagged-route-table" listing its attachments; the table is skipped until tagged.

## The intent file

Three checks need to know what you *intend*, which neither the Cloud WAN policy nor your tags can say: which TGW route tables may see each other, which Direct Connect VIFs back each other up, and how important prefixes should leave AWS. You describe that in one short YAML file. Without it, those three checks are skipped and the report says so. The checker only ever reads the file.

A complete example is in [`examples/routing-intent.example.yaml`](examples/routing-intent.example.yaml):

```yaml
version: 1

tgw_isolation:
  prod:   [shared]
  dev:    [shared]
  shared: [prod, dev]

dx_redundancy_pairs:
  - name: frankfurt-site-a
    members: [dxvif-0123abcd, dxvif-0456efgh]

hybrid_paths:
  - prefix: 10.100.0.0/16
    exit_region: eu-central-1
  - prefix: 192.168.0.0/16
    preferred: dxvif-0123abcd
    backup: vpn-0abc1234
```

Upload it (it is checked locally first, and every upload is kept as a version in the stack's bucket):

```bash
scripts/upload-intent.sh my-routing-intent.yaml
```

The next run uses it. To check it straight away, [run on demand](#run-it-on-demand).

The file decides what counts as drift, so treat write access to it like write access to your routing: limit `s3:PutObject` on the bucket's `intent/` prefix to the network team. Every upload is kept as an S3 version, and each run records which version it used.

### Sections

All sections except `version` are optional.

| Section | What you write | What the checker reports |
|---|---|---|
| `version` | Always `1` | |
| `tgw_isolation` | For each route table, the tables whose routes it may see. Names are `Environment` tag values or route table IDs (`tgw-rtb-…`), case-insensitive. A table always sees itself. | A route in a listed table whose next-hop attachment belongs to a domain not in its list: one finding per prefix and source. Tables you don't list are not checked. |
| `dx_redundancy_pairs` | A `name` and exactly two VIF IDs (`dxvif-…`) that back each other up | A member that doesn't exist, isn't `available`, or has a BGP session down; and both members down at once |
| `hybrid_paths` | A `prefix` plus at least one of: `exit_region` (Region code), `preferred` and/or `backup` (a VIF, TGW attachment, Cloud WAN attachment, VPN or Direct Connect gateway ID) | Prefix not installed anywhere; installed with a next hop in another Region; not routed via `preferred` in that resource's Region; `backup` missing or unhealthy |
| `regions` | `allow` and/or `exclude` lists of Region codes | Non-empty lists replace the matching stack parameter. An ad-hoc run's input still wins. |

Two things the checker can't see, so it doesn't guess:

- **A standby backup.** AWS APIs show only the routes in use. When the backup isn't carrying the prefix, the checker confirms the backup itself is healthy (VPN tunnel up, VIF and BGP up, attachment available) and reports an informational "can't verify it advertises the prefix" rather than drift.
- **Anything in a Region it couldn't check.** If a VIF, attachment or prefix isn't found while a Region was not evaluated, the finding says "not verified," never "missing."

### When the file is rejected

A broken file never stops the other checks. The report lists it under NOT VERIFIED with every problem, in line order, so you can fix them in one pass. For example, a file with a misspelled section and a one-member pair produces:

```
line 2: the intent file: unknown key 'dx_redundency_pairs' (allowed: version, tgw_isolation, dx_redundancy_pairs, hybrid_paths, regions)
line 5: dx_redundancy_pairs.a.members must list exactly two different VIF IDs
```

`scripts/upload-intent.sh` prints the same messages and refuses to upload. One more check happens at run time: a `tgw_isolation` name that matches no route table ID or tag value rejects the file, because a typo would otherwise silently switch the check off.

## Optional: investigation with AWS DevOps Agent

When this is enabled, the NEW drift findings of a run are handed to an [AWS DevOps Agent](https://aws.amazon.com/devops-agent/) Agent Space. DevOps Agent looks for the change event (CloudTrail) or AWS Health event behind each finding, groups related findings into incidents, and the report then shows them ranked (see [Reading the report](#reading-the-report)). Without it, the checker works exactly the same and says "No investigation was performed".

Only NEW findings are investigated, so a finding costs one investigation once, not every day. In our tests, an investigation took 12 to 16 minutes; the checker waits up to 45 minutes per batch (`INVESTIGATION_TIMEOUT_SECONDS`) and up to 25 findings go into one investigation.

### Choose a shape

| Shape | When | What's deployed |
|---|---|---|
| **Same account** | The Agent Space lives in the networking account | Only the checker stack |
| **Cross-account** | The Agent Space lives in a central operations account (common) | The checker stack in the networking account, plus a small `NetworkRoutingDriftChecker-DevOpsAgentLink` stack in the Agent Space account |

Both shapes need the Agent Space in **the same Region** as the checker. DevOps Agent publishes its events in its own Region, and EventBridge delivers to another account only within one Region. The deploy script refuses a webhook URL from another Region.

### 1. Prepare the Agent Space

1. **Connect the networking account.** Same account: it's the Agent Space's primary account. Cross-account: in the Agent Space, Capabilities → Cloud → Secondary sources → Add, and create the role it describes in the networking account ([Connecting multiple AWS accounts](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-integrations-and-knowledge-connecting-multiple-aws-accounts.html)).
2. **Give that role read access.** Attach the AWS managed policy `AIDevOpsAgentAccessPolicy` to the Agent Space's role in the networking account. It covers CloudTrail, AWS Health, Transit Gateway, Direct Connect and most Network Manager reads. Then add the two Cloud WAN reads it doesn't include, with this template in the networking account:
   ```bash
   aws cloudformation deploy --stack-name nrdc-devops-agent-network-reads \
     --template-file cloudformation/devops-agent-network-reads.yaml \
     --parameter-overrides DevOpsAgentRoleName=<role name, e.g. DevOpsAgentRole-AgentSpace-abc123>
   ```
   It adds `networkmanager:GetNetworkRoutes` and `networkmanager:GetCoreNetworkChangeEvents`, scoped to your account's global networks and core networks. Without these reads the investigation still runs, but mostly answers "No evidence found" at low confidence.
3. **Upload two skills** in the Agent Space (Operator Web App → Knowledge → Skills → Add skill → Upload skill, agent type Generic):
   - `network-routing-drift`: build the zip with `scripts/package-skill.sh` (writes `dist/network-routing-drift.zip`). It tells DevOps Agent how to investigate each finding type and the exact result format the checker reads.
   - [`aws-routing`](https://github.com/aws/tools-for-devops-agent/tree/main/skills/aws-routing), the public route-evaluation skill. Import it from the repository (needs a GitHub connection on the Agent Space) or zip its directory and upload it.
4. **Create a generic webhook with HMAC authentication** in the Agent Space. Copy the URL (`https://event-ai.<region>.api.aws/webhook/generic/<id>`) and the secret: the secret is shown only once. Each Agent Space allows one HMAC webhook. If yours is already used by another integration, either point the checker at the same webhook (the callback only acts on investigations it started, so the two don't interfere, but they share the secret) or use a separate Agent Space.
5. **Store the secret** in AWS Systems Manager Parameter Store in the **networking account**, as a SecureString whose name starts with `/`:
   ```bash
   read -rs SECRET && aws ssm put-parameter --type SecureString \
     --name /network-drift/devops-agent-webhook-secret --value "$SECRET" && unset SECRET
   ```
   The checker reads it at run time; it's never in an environment variable, a log or the stack. The default `aws/ssm` key needs no extra permission. If you use your own KMS key, allow the `InvestigateFunction` role `kms:Decrypt` on it.
6. **Keep CloudTrail on** for management events in the evaluated Regions and in us-west-2 (Network Manager). Without a trail there's nothing to find.

### 2. Enable it

Add to `.deploy.env` and run `scripts/deploy.sh` again:

```bash
ENABLE_DEVOPS_AGENT_HANDOFF=true
DEVOPS_AGENT_WEBHOOK_URL=https://event-ai.<region>.api.aws/webhook/generic/<id>
WEBHOOK_SECRET_PARAMETER_NAME=/network-drift/devops-agent-webhook-secret
DEVOPS_AGENT_SPACE_ID=<Agent Space ID>
# Cross-account only:
DEVOPS_AGENT_ACCOUNT_ID=<Agent Space account ID>
DEVOPS_AGENT_PROFILE=<AWS CLI profile for that account>
```

All of URL, secret name and space ID are required together; a partial set fails the deploy. Before deploying, the script checks the webhook's Region and that the secret parameter is a SecureString.

**Cross-account,** the same command then deploys the link stack into the Agent Space account with `DEVOPS_AGENT_PROFILE` (that account must be [CDK-bootstrapped](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html) in the Region) and checks the link: both link roles exist, the journal reader trusts only the checker's callback role, the callback accepts events from the Agent Space account, and the callback role may assume the reader. If any of that fails, the deploy fails and says which part is missing, so a half-working hand-off never stays in place.

The link stack contains no data and no compute, only:

- an EventBridge rule that forwards this one Agent Space's investigation events to the checker's callback function;
- the rule's role, allowed to invoke only that function;
- a read-only role that only the checker's callback role can assume, allowed only `aidevops:ListJournalRecords` on this one Agent Space.

To try it, upload an intent file entry that produces one NEW finding and [run on demand](#run-it-on-demand); the report should arrive with an INVESTIGATION section.

### Limits and cost

- Investigations count against your Agent Space's investigation allowance and are billed as DevOps Agent usage, separately from the checker. Check the limits and pricing for your Agent Space before enabling it on a network with many changes.
- **Known limitation: grouping quality hasn't been scored yet.** These are enforced by code and seen in our live tests: no change commands in the report, the result format, "No evidence found" instead of invented causes, and the raw-findings fallback. The ranking order is computed by the checker. Whether DevOps Agent reliably groups many findings with one cause (for example one VIF down and the prefixes it carried) into one incident hasn't been measured, because our test account had no Direct Connect VIFs. If it groups poorly, you'll see more incidents than necessary; the findings, evidence and order stay correct.
- To turn it off, set `ENABLE_DEVOPS_AGENT_HANDOFF=false` and clear the other DevOps Agent settings, then deploy again. Cross-account, also remove the link stack (see [Remove it](#remove-it)).

## Permissions

The checker can **read** your network and **write only to its own resources**. Every role is per function, and none has a managed policy.

| Function | Reads in your account | Writes (own resources only) |
|---|---|---|
| Init | `ec2:DescribeRegions`, `ec2:DescribeTransitGateways`, `networkmanager:ListCoreNetworks`, `networkmanager:GetCoreNetwork`, `directconnect:DescribeDirectConnectGateways`, `directconnect:DescribeDirectConnectGatewayAssociations`, `directconnect:DescribeVirtualInterfaces`; reads the intent file | Run artifacts in its bucket |
| Collect Cloud WAN | `networkmanager:ListCoreNetworks`, `GetCoreNetwork`, `GetCoreNetworkPolicy`, `ListAttachments`, `GetNetworkRoutes` | Run artifacts |
| Collect Region | `ec2:DescribeTransitGateways`, `DescribeTransitGatewayRouteTables`, `DescribeTransitGatewayAttachments`, `SearchTransitGatewayRoutes`, `DescribeVpnConnections`, `directconnect:DescribeVirtualInterfaces` | Run artifacts |
| Evaluate, Report | none | Run artifacts |
| Diff | none | Finding history in its DynamoDB table |
| State machine | none | Invoke its functions, publish to its topic, update its marker item |
| Batch findings, Merge investigations | none | Run artifacts; task-token items in its table |
| Investigate (hand-off on) | `ssm:GetParameter` on the one secret parameter | Task-token items in its table; HTTPS to the webhook URL |
| Callback (hand-off on) | Same account: `aidevops:ListJournalRecords` on the one Agent Space. Cross-account: `sts:AssumeRole` on the one journal-reader role instead | `states:SendTaskSuccess`/`Failure`/`Heartbeat` on this state machine only; task-token items; run artifacts; its dead-letter queue |

The hand-off grants exist only when the hand-off is enabled, and only for the shape you chose. The `states:SendTask*` grant is scoped to the checker's state machine and was verified to work that way. The investigation itself runs under the Agent Space's own role, not the checker's.

`DescribeRegions`, `DescribeTransitGateways`, `DescribeTransitGatewayRouteTables`, `DescribeTransitGatewayAttachments`, `DescribeVpnConnections`, and the Network Manager `ListCoreNetworks` call don't support resource-level permissions, so those reads use `Resource: "*"`. Everything else is scoped: Network Manager's other reads to core network, attachment and global network ARNs; `SearchTransitGatewayRoutes` to this account's transit gateway route tables; the Direct Connect gateway reads to this account's `dx-gateway` ARNs; the Direct Connect VIF reads to this account's `dxcon`/`dxlag`/`dxvif` ARNs. A deny-by-default lint (`tests/iam/`) fails the build if any action outside this list, any wildcard action, or any write outside the stack's own resources appears.

Data at rest is encrypted with one customer-managed AWS KMS key (rotation on). The bucket is private, versioned and TLS-only. The stack exposes **no inbound endpoint**: investigation results arrive as EventBridge events, and the callback only acts on events whose investigation carries its own `[INVESTIGATION_ID:nrdc-…]` tag and a live task token. Cross-account, the callback accepts invocations from the Agent Space account, where only the link stack's rule role may invoke it.

With the hand-off enabled, the NEW findings of a run (resource IDs, prefixes, tag values and messages) leave the account as the webhook request to your Agent Space. Nothing else does.

## Cost

Measured in a lab account in us-east-1 (2026-10-16): 3 Regions, 8 Transit Gateway route tables, one Cloud WAN core network. A scheduled daily run took 24 seconds with 16 state transitions and 10 Lambda invocations (about 15 s of compute at 512 MB, arm64). A run that also hands one batch to DevOps Agent adds 3 transitions and 3 to 5 short invocations; the wait for the investigation is not billed. List prices from the AWS Price List API, before free tiers:

| Item | Measured usage per month (30 daily runs) | Cost per month |
|---|---|---|
| AWS KMS customer-managed key | 1 key, a few thousand requests | USD 1.00 |
| CloudWatch alarms, billed per metric (USD 0.10 each) | 11 alarms, 19 metrics: the failed-run alarm uses 3, each Lambda error-rate alarm 2 | USD 1.90 |
| AWS Step Functions (USD 0.025 per 1,000 transitions) | about 500 transitions | USD 0.01 |
| AWS Lambda (arm64, USD 0.0000133334 per GB-s) | about 230 GB-s, 300 requests | USD 0.01 |
| Amazon DynamoDB on demand, Amazon S3, Amazon SNS, CloudWatch Logs, AWS X-Ray | under 1,000 writes, under 1 MB of logs | under USD 0.05 |
| **Total** | | **about USD 3.00** |

A larger network mostly adds Lambda time in the collect step, which stays in cents. The fixed items (key and alarms) are 97 % of the bill.

The optional DevOps Agent investigations are billed by DevOps Agent and are not in this figure; only NEW findings are investigated. The link stack in a second account has no running cost (one EventBridge rule and two roles; cross-account event delivery is charged per event and is negligible at a few events per investigation).

Prices vary by Region; check [AWS KMS](https://aws.amazon.com/kms/pricing/), [Amazon CloudWatch](https://aws.amazon.com/cloudwatch/pricing/), [AWS Step Functions](https://aws.amazon.com/step-functions/pricing/) and [AWS Lambda](https://aws.amazon.com/lambda/pricing/) pricing.

## Troubleshooting

| Symptom | Check |
|---|---|
| No message at all | Is the SNS e-mail subscription confirmed? Look at the Step Functions execution history and the `MissedRunAlarm` / `ExecutionFailedAlarm` alarms. |
| "Region X not evaluated: …" | Usually throttling, an SCP, or a Region you can't reach. It retries automatically; the reason is in the message. Three days in a row raises `RegionsNotEvaluatedAlarm`. Findings in that Region stay KNOWN and "not re-verified" instead of being marked resolved. |
| "Cloud WAN not evaluated" | Network Manager (us-west-2) was unreachable or denied. Check SCPs that restrict us-west-2. |
| "Intent file rejected: line N: …" | Fix the listed lines (see [When the file is rejected](#when-the-file-is-rejected)) and upload again with `scripts/upload-intent.sh`. Until then the three intent checks are skipped; the other checks still run. "matches no route table ID or Environment tag value" means a `tgw_isolation` name is misspelled or the table is in a Region that wasn't checked. |
| "Intent file unreadable" | The checker could not read `intent/routing-intent.yaml` in its bucket, usually because of a bucket or KMS key policy you changed. |
| "redundancy-member-missing" for a VIF you know exists | The VIF ID is wrong, or the VIF is owned by another account (this version is single-account). |
| "hybrid-path-backup-unverifiable" | Informational: the backup is healthy but not carrying the prefix right now, which is normal for a standby path. |
| Many "untagged-…" lines | Add the `Environment` tag (see [Tag convention](#tag-convention-transit-gateway)). |
| "Investigation failed: batch N: timeout-never-started" | DevOps Agent never started the investigation. Check the webhook URL, that the secret in SSM matches the webhook's current secret (update both together if you rotate it), and the Agent Space's investigation allowance. |
| "… timeout-running" | The investigation started but took longer than `INVESTIGATION_TIMEOUT_SECONDS` (default 45 minutes). Raise it in `.deploy.env` and deploy again. |
| "… NO_RESULT" | The investigation finished without the result block. Check that the `network-routing-drift` skill is uploaded and Active in the Agent Space. |
| "… SCHEMA_INVALID" | The result block didn't match the batch (for example a missing finding ID). The callback log names the rule that failed; the investigation link still works. |
| "… JOURNAL_ACCESS_DENIED" | The callback couldn't read the investigation. Same account: its role needs `aidevops:ListJournalRecords` on the Agent Space. Cross-account: the link stack is missing or out of date; run `scripts/deploy.sh` again. |
| `CallbackDlqMessagesAlarm` | An investigation event couldn't be processed after retries. See the callback's CloudWatch logs; the affected batch is reported as timed out. |
| "the cross-account hand-off is not complete" during deploy | The probe lists what's missing: a link role, the reader's trust, or the callback's permission. Usually the link stack failed or `DEVOPS_AGENT_PROFILE` points at the wrong account. |
| Investigations always say "No evidence found" | The Agent Space's role in the networking account lacks read access (`AIDevOpsAgentAccessPolicy` plus `cloudformation/devops-agent-network-reads.yaml`), or no CloudTrail trail covers the Region. |

## Remove it

```bash
scripts/destroy.sh
```

Cross-account, set `DEVOPS_AGENT_PROFILE` first; the script then removes the link stack in the Agent Space account before the checker. The skills, the webhook and the secret parameter are yours to remove.

This deletes the stack. The bucket, the finding-history table and their KMS key are **kept** so history isn't lost. The script prints their names; delete them yourself when you no longer need them.

## Development

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
(cd infra && npm ci)
.venv/bin/pytest tests --cov=src --cov-report=json:coverage.json && .venv/bin/python scripts/coverage_gate.py
```

Tests need no AWS credentials. Collector tests replay sanitized responses recorded from a lab account (`tests/fixtures/recorded/`); `scripts/record_fixtures.py` records new ones read-only. The design and requirements live in `.kiro/specs/network-routing-drift-checker/`.

## License

MIT-0. See [LICENSE](LICENSE).
