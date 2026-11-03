---
name: network-routing-drift
description: 'Investigate routing drift findings reported by the network-routing-drift-checker for AWS Cloud WAN, AWS Transit Gateway and AWS Direct Connect. Activate when an incident or webhook description starts with "[INVESTIGATION_ID:nrdc-" or contains "NETWORK ROUTING DRIFT — NEW FINDINGS", or when asked why a blackhole route, prefix leak, wrong segment or route table, Direct Connect redundancy or BGP failure, route-limit threshold, or hybrid-path exit/backup finding appeared. Finds the change event (CloudTrail) or AWS Health event behind each finding, groups related findings into incidents, ranks them by blast radius, and ends with a fixed nrdc-investigation/v1 JSON block that the checker parses. Read-only: evidence, hypotheses and describe/get/list/search validation commands only, never remediation. Use together with the aws-routing skill.'
metadata:
  version: "1.0.0"
  author: network-routing-drift-checker
---

# Network routing drift investigation

The network-routing-drift-checker compares live routing in one AWS account with the customer's
intended design and hands you the **NEW** drift findings of one run. The checker has already
decided, with deterministic code, that each finding is drift. Your job is to explain each one,
group them, rank them, and return a structured block. You don't re-decide whether something is drift.

Apply the `aws-routing` skill for route-evaluation logic: which table, segment or Direct Connect
gateway made the routing decision, and why.

## Mandatory output rule

**Your final message MUST end with exactly one fenced `json` block, using the template in
"Output block" below.** The checker reads that block and nothing else. If it's missing or invalid,
your investigation is discarded and the customer gets raw findings. Check every rule in "Before you
answer" first.

## Input you receive

```
[INVESTIGATION_ID:nrdc-<run_id>-<batch_n>]
NETWORK ROUTING DRIFT — NEW FINDINGS (run <run_id>, lookback from <time>)
Account <account>. Batch <n> of <m>. Skill to apply: network-routing-drift (with aws-routing).
[1] id=f-<20 hex> kind=<kind> region=<region|global> check=<checkN>
    <one-line message>
    expected: {...}  observed: {...}
    context: {...}
...
Lookback window for change events: <from> → <to>.
```

- The `incidentId` you return is the value inside `[INVESTIGATION_ID:...]`, copied exactly.
- The **finding IDs** are the `id=f-...` values. Every one must appear exactly once in your block.
- The **lookback window** bounds your change-event search. Search it, and only extend before it
  when the window is empty, saying so in `notes`.
- What each `kind` means and which fields it carries is in `references/finding-kinds.md`.

## Procedure

1. **Read every finding.** Note the resource IDs (`tgw-rtb-`, `tgw-attach-`, `dxvif-`,
   `attachment-`, `vpn-`, `core-network-`), the prefixes and the `Environment` values in `context`.
2. **Confirm the observed state** with read-only calls. Record each fact as `state` evidence, for
   example route state `blackhole`, `bgpStatus=down` or `virtualInterfaceState=deleted`. Network
   Manager (AWS Cloud WAN) is called in **us-west-2**. Transit Gateway, Direct Connect and VPN are
   called in the finding's Region.
3. **Look for the change.** Use CloudTrail `LookupEvents` in the lookback window, filtered by the
   resource ID (`ResourceName`) or the event names in `references/cloudtrail-event-map.md`. Cloud WAN
   events are recorded in us-west-2. Record each matching event as `cloudtrail` evidence, with its
   `eventID`, `eventName`, `eventTime` and the actor (`userIdentity.arn`, or `unknown`).
4. **Look for an AWS Health event** on the affected resources in the same window
   (`references/health-event-map.md`). Record matches as `health` evidence with the event ARN.
5. **Explain the routing decision** with `aws-routing`: which table, segment or gateway installed
   or dropped the route, and why. That explanation goes into `root_cause_hypothesis`.
6. **Group** findings into incidents (rules below).
7. **Count the blast radius** of each incident and rank (rules below).
8. **Write validation commands**: read-only checks a human can run to confirm the hypothesis.
9. **Emit the block.**

### Per finding family

| Family (kinds) | What to look for |
|---|---|
| Blackhole, missing or unexpected route: `blackhole-route`, `*-prefix-leak`, `cloudwan-isolation-leak`, `hybrid-path-*` | The change that created, replaced or orphaned the route: a deleted attachment behind a static route, a new or changed propagation, a policy version change. Name the table or segment that made the decision. |
| Wrong routing domain: `cloudwan-wrong-segment`, `tgw-wrong-route-table` | The attachment creation or association event, a tag change that moved it (`TagResource` / `CreateTags` on the attachment), or a core network policy version change. |
| Direct Connect redundancy: `redundancy-*` | VIF state and BGP peer state now; an AWS Health Direct Connect event (maintenance or outage) at the location; a `DeleteVirtualInterface` / `DeleteBGPPeer` event; whether the surviving member still carries the pair's prefixes. |
| Limit threshold: `limit-threshold` | Which prefixes or routes were added most recently (change events in the window), and whether the limit is adjustable (state the documented limit; don't guess). |

## Grouping rules

- One incident = one root cause. One VIF down and the twelve prefixes it carried = **one** incident
  with all thirteen finding IDs, not thirteen incidents.
- Findings that share a resource (same route table, VIF, attachment) and a cause belong together.
  Shared resources alone are not enough: if the causes differ, keep them apart.
- A finding you couldn't explain at all goes into `unassigned_finding_ids`, not into a made-up
  incident.
- **Every finding ID of the input appears exactly once** across all `member_finding_ids` and
  `unassigned_finding_ids`. No ID that isn't in the input.

## Evidence, confidence and the actor

- **Every hypothesis cites its evidence:** a CloudTrail event ID, an AWS Health event ARN, or an
  observed state. Never cite something you didn't retrieve.
- **No evidence found:** if CloudTrail and AWS Health return nothing for the window, say exactly
  "No evidence found" in `root_cause_hypothesis`, then give the most likely mechanism as a
  hypothesis only. Set `confidence` to `low`. Don't fill the gap with a plausible story.
- **Confidence scale (fixed):**
  - `high`: a direct matching change event in the window (CloudTrail, with the resource named).
  - `medium`: circumstantial: timing, a related AWS Health event, or a partial match.
  - `low`: no change or AWS Health evidence; state observations only.
- **Unknown actor:** set `actor_identified` to `false` and say why. For example: the change was
  service-driven (attachment mapping by policy), older than CloudTrail retention, in a Region the
  trail doesn't capture, or no event was found at all.
- **Stability:** `stable_for` is how long the finding has been present, as an ISO-8601 duration.
  These findings are NEW in this run, so use `"P0D"` unless the input states an earlier first
  sighting. Report it as a fact only. Never infer that a long-standing finding is intentional.

## Blast radius and rank

For each incident, count from the findings and the observed state:

- `prefixes`: distinct affected prefixes.
- `attachments`: distinct affected attachments, VIFs or VPN connections.
- `domains`: distinct affected Cloud WAN segments or Transit Gateway route tables.
- `environment`: the `Environment` value of the most production-like affected domain (`prod`
  before `staging` before anything else), or `""` if untagged.

Then `score = (prefixes + 10 × attachments + 100 × domains) × weight`. The weight is 10 for
production, 3 for staging or shared, and 1 otherwise. `rank` 1 = highest score. Ties go to higher
confidence, then to the family order blackhole, redundancy, leak, wrong-domain, limit, hybrid-path.
Ranks are a permutation of 1..n with no gaps. The checker recomputes the score from your counts,
so count carefully. The arithmetic itself is checked.

## Hard boundaries

- **Read-only.** Only `describe-*`, `get-*`, `list-*`, `search-*` calls (and CloudTrail
  `LookupEvents`). Never `create-*`, `modify-*`, `delete-*`, `replace-*`, `associate-*`,
  `disassociate-*`, `put-*`, `update-*`, `attach-*`, `detach-*`, `accept-*`, `reject-*`,
  `enable-*`, `disable-*`, `execute-*` or `restore-*`.
- **No remediation commands.** You may describe in prose what a human could change, labeled
  "Recommendation for a human, verify first". Never as a command, and never in
  `validation_commands`. This applies to mitigation steps too: for an `nrdc-` incident, a
  mitigation is a prose recommendation with read-only validation, never a change plan with commands.
- Never suggest editing the customer's intent file or the checker's settings, and never suggest
  adding an entry to "make the finding go away".
- No claim that can't be grounded in data you retrieved from this account or in public AWS
  documentation. If you can't verify something, say "I cannot verify this".

## Validation commands

Each entry must:

- match `aws <service> <describe|get|list|search>-<operation> ...`, all lowercase;
- use only `ec2`, `networkmanager` or `directconnect` as `<service>` — no other service, even a
  read-only one (for example `secretsmanager get-secret-value` or `s3api get-object` are rejected
  outright, regardless of the operation name);
- contain no `;`, `&&`, `|`, `` ` ``, `$(`, `>`, `<`, or a literal newline;
- contain no `--endpoint-url`, `--cli-input-json`, `--cli-input-yaml`, `--generate-cli-skeleton`,
  `--no-verify-ssl`, `--ca-bundle`, `file://` or `fileb://` — these change where or how the request
  is sent (or let it read/write an arbitrary local file) rather than what it reads from AWS;
- have every token after the operation be a flag or a flag's value — no bare positional argument
  (this is also why no command can be an `s3api` upload/download: the local file path is always a
  positional or trailing argument, and the validator rejects it on that basis alone, independent of
  the service allowlist above);
- have at most 20 entries per incident.

CloudTrail `lookup-events` does **not** match this pattern. Cite CloudTrail as `cloudtrail` evidence
instead, and don't list it as a command.

Examples:

- `aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-0abc --filters Name=route-search.exact-match,Values=10.1.0.0/16 --region eu-central-1`
- `aws directconnect describe-virtual-interfaces --virtual-interface-id dxvif-0abc --region eu-central-1`
- `aws networkmanager get-network-routes --global-network-id global-network-0abc --route-table-identifier '{"CoreNetworkSegmentEdge":{"CoreNetworkId":"core-network-0abc","SegmentName":"prod","EdgeLocation":"eu-central-1"}}' --region us-west-2`

## Output block

End your final message with this block, filled in. Field rules:

- Keys and value types exactly as shown.
- `evidence` items are one of the three shapes shown.
- `investigation_url` and `notes` are optional.
- The full schema is in `references/output-schema.json`.

```json
{
  "schema": "nrdc-investigation/v1",
  "incidentId": "nrdc-2026-10-13T05:00:00Z-a1b2c3d4-1",
  "incidents": [
    {
      "rank": 1,
      "title": "Orphaned static route blackholes 10.100.0.0/16 in the prod route table",
      "member_finding_ids": ["f-0123456789abcdef0123"],
      "root_cause_hypothesis": "The VPC attachment behind a static route was deleted, leaving the route in blackhole state. The prod route table therefore drops 10.100.0.0/16 instead of propagating it.",
      "confidence": "high",
      "evidence": [
        {"type": "cloudtrail", "event_id": "3f2a1b9c-0000-4000-8000-000000000001", "event_name": "DeleteTransitGatewayVpcAttachment", "time": "2026-10-12T14:03:11Z", "actor": "arn:aws:sts::123456789012:assumed-role/NetworkAdmin/jdoe"},
        {"type": "health", "event_arn": "arn:aws:health:eu-central-1::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/EXAMPLE"},
        {"type": "state", "resource": "tgw-rtb-0abc", "observation": "10.100.0.0/16 static, state blackhole, no attachment"}
      ],
      "actor_identified": true,
      "blast_radius": {"prefixes": 1, "attachments": 1, "domains": 1, "environment": "prod", "score": 1110},
      "stable_for": "P0D",
      "validation_commands": [
        "aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-0abc --filters Name=state,Values=blackhole --region eu-central-1"
      ]
    }
  ],
  "unassigned_finding_ids": [],
  "notes": "Only state the facts the checker can't see, for example a CloudTrail retention gap."
}
```

### Before you answer

- [ ] `incidentId` equals the `[INVESTIGATION_ID:...]` value of the input, character for character.
- [ ] Every input finding ID appears exactly once across incidents and `unassigned_finding_ids`, and
      no other ID appears.
- [ ] `rank` values are 1..n with no gaps or repeats.
- [ ] `confidence` is `high`, `medium` or `low`, and matches the evidence rules.
- [ ] Every validation command starts with `aws <service> describe-|get-|list-|search-` and has no
      `;`, `&&` or `|`.
- [ ] `stable_for` is an ISO-8601 duration such as `P0D`.
- [ ] The block is valid JSON (no comments, no trailing commas) and is the last thing in the message.
