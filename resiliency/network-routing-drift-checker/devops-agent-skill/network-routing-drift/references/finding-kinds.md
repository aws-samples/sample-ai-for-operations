# Finding kinds

Only **drift** findings are sent for investigation. Each one arrives as:

```
[n] id=f-<20 hex> kind=<kind> region=<region|global> check=<checkN>
    <message>
    expected: {...}  observed: {...}
    context: {...}
```

`region=global` means the finding isn't tied to one Region: Cloud WAN (collected once through
us-west-2), or a hybrid-path prefix evaluated across all Regions. `context` carries the resource IDs,
the prefixes and the `Environment` tag value(s) where the checker knows them.

| Kind | Check | Meaning | Family | Start with |
|---|---|---|---|---|
| `cloudwan-wrong-segment` | 1 | A Cloud WAN attachment is in a different segment than the core network policy's attachment rules assign. | wrong-domain | The attachment's tags and segment now; `PutCoreNetworkPolicy` / `ExecuteCoreNetworkChangeSet` and attachment tag changes in the window. |
| `tgw-wrong-route-table` | 1 | A TGW attachment is associated with a route table whose `Environment` tag differs from the attachment's. | wrong-domain | The association (`AssociateTransitGatewayRouteTable`, `ReplaceTransitGatewayRouteTableAssociation`), or a tag change on either side. |
| `cloudwan-prefix-leak` | 2 | A segment's route table at an edge has a route from a segment it doesn't share with in the policy. | leak | Segment `share` / segment-action changes in the policy; the routes in that segment edge. |
| `cloudwan-isolation-leak` | 2 | A segment with `isolate-attachments` has a route learned from another attachment of the same segment. | leak | Policy version changes; whether `isolate-attachments` was turned on recently. |
| `tgw-prefix-leak` | 2 | A TGW route table has a route via an attachment whose table the intent file says it must not see. | leak | Propagations into the table (`EnableTransitGatewayRouteTablePropagation`), static routes (`CreateTransitGatewayRoute`). |
| `blackhole-route` | 3 | A route is in `blackhole` state: a TGW static route whose attachment is gone, or a Cloud WAN blackhole route. | blackhole | The deleted attachment (`DeleteTransitGatewayVpcAttachment`, `DeleteAttachment`) or `CreateTransitGatewayRoute --blackhole`. |
| `redundancy-member-missing` | 4 | A VIF named in a declared redundancy pair doesn't exist in any evaluated Region. | redundancy | `DeleteVirtualInterface`; whether the ID was ever valid (no event in the window → say so). |
| `redundancy-member-down` | 4 | A pair member's VIF is not `available`. | redundancy | VIF state and AWS Health Direct Connect events at its location. |
| `redundancy-bgp-down` | 4 | A pair member's BGP peer is not `up`. | redundancy | BGP peer state; AWS Health; `DeleteBGPPeer`; on-premises side is outside the account (say so). |
| `redundancy-pair-down` | 4 | Both members of a pair are down or missing: no working path. | redundancy | Group with the member findings of the same pair: one incident. |
| `limit-threshold` | 5 | A route or prefix count crossed its threshold of a documented limit. `context` names the limit and its value. | limit | The most recently added routes or prefixes; whether the limit is adjustable (cite the doc). |
| `hybrid-path-wrong-exit-region` | 6 | A prefix declared to exit via Region X is installed with next hops in other Regions. | hybrid-path | Which table installed it and from which attachment; DX gateway associations and allowed prefixes. |
| `hybrid-path-prefix-not-found` | 6 | A declared hybrid prefix is not installed in any evaluated route table. | hybrid-path | Whether the advertising attachment or VIF exists and is up; a blackhole route for the same prefix; withdrawn allowed prefixes. |
| `hybrid-path-not-preferred` | 6 | A prefix is installed via an attachment other than the declared preferred one. | hybrid-path | The preferred attachment's state; route preference (`aws-routing`: longest prefix, static over propagated, AS-path). |
| `hybrid-path-backup-absent` | 6 | The declared backup attachment or VIF is not available. | hybrid-path | The backup's state (VPN tunnels, VIF state, BGP). |

Never investigated (not drift, so they don't reach you): informational notes (`untagged-*`,
`cloudwan-no-matching-rule`, `cloudwan-segment-change-pending`, `hybrid-path-backup-unverifiable`)
and "not verified" notes (`*-unverified`, `cloudwan-rule-not-evaluated`, `region-not-evaluated`,
`intent-file`).
