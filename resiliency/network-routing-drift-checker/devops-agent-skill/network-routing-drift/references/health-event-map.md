# AWS Health events per finding family

Query AWS Health (`DescribeEvents` filtered by service, Region and the window; then
`DescribeAffectedEntities` to match the resource) for events overlapping the lookback window.

| Family | AWS Health service | Event type code families to look for |
|---|---|---|
| redundancy | `DIRECTCONNECT` | `AWS_DIRECTCONNECT_MAINTENANCE_SCHEDULED`, `AWS_DIRECTCONNECT_EMERGENCY_MAINTENANCE_SCHEDULED`, `AWS_DIRECTCONNECT_OPERATIONAL_ISSUE`, and other `AWS_DIRECTCONNECT_*` codes naming the connection, LAG or VIF |
| blackhole, hybrid-path | `EC2` (Transit Gateway, VPN), `DIRECTCONNECT`, `NETWORKMANAGER` / `CLOUDWAN` | `AWS_EC2_OPERATIONAL_ISSUE`, `AWS_VPN_*` (tunnel maintenance or redundancy loss), `AWS_DIRECTCONNECT_*`, Cloud WAN operational issues |
| leak, wrong-domain, limit | rarely caused by AWS Health events | Check only if a change event is missing and timing suggests a service event |

Use only codes you see in the returned events; this table lists families, not a closed set.

Recording a match as evidence:

```json
{"type": "health", "event_arn": "<event ARN>"}
```

An AWS Health event alone, without a matching affected entity, is circumstantial: `medium` confidence
at most.
