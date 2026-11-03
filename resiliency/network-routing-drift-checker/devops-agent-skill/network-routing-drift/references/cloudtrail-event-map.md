# CloudTrail events per finding family

Search with `LookupEvents` in the lookback window. Filter by `ResourceName` = the resource ID
first (it's the most precise). If that returns nothing, filter by `EventName` and match the
resource in the event's request parameters. Events of Network Manager (AWS Cloud WAN) are recorded in
**us-west-2**. Transit Gateway, Direct Connect and VPN events are recorded in the resource's Region.

| Family | Event names (source) |
|---|---|
| blackhole | `DeleteTransitGatewayVpcAttachment`, `DeleteTransitGatewayPeeringAttachment`, `DeleteTransitGatewayConnect`, `DeleteVpnConnection`, `CreateTransitGatewayRoute`, `ReplaceTransitGatewayRoute` (ec2); `DeleteAttachment`, `PutCoreNetworkPolicy`, `ExecuteCoreNetworkChangeSet` (networkmanager) |
| leak | `EnableTransitGatewayRouteTablePropagation`, `CreateTransitGatewayRoute`, `ReplaceTransitGatewayRoute`, `AssociateTransitGatewayRouteTable` (ec2); `PutCoreNetworkPolicy`, `ExecuteCoreNetworkChangeSet` (networkmanager) |
| wrong-domain | `AssociateTransitGatewayRouteTable`, `DisassociateTransitGatewayRouteTable`, `ReplaceTransitGatewayRouteTableAssociation`, `CreateTags`, `DeleteTags` (ec2); `TagResource`, `UntagResource`, `PutCoreNetworkPolicy`, `ExecuteCoreNetworkChangeSet`, `AcceptAttachment` (networkmanager) |
| redundancy | `DeleteVirtualInterface`, `DeleteBGPPeer`, `CreateBGPPeer`, `DisassociateVirtualInterface`, `DeleteDirectConnectGatewayAssociation`, `UpdateDirectConnectGatewayAssociation` (directconnect) |
| limit | `CreateTransitGatewayRoute`, `EnableTransitGatewayRouteTablePropagation` (ec2); `UpdateDirectConnectGatewayAssociation`, `AllocateTransitVirtualInterface` (directconnect); `PutCoreNetworkPolicy` (networkmanager) |
| hybrid-path | All of the above for the attachment or VIF that should carry the prefix, plus `UpdateDirectConnectGatewayAssociation` (allowed prefixes) and `DeleteVpnConnectionRoute`, `ModifyVpnConnection` (ec2) |

Recording a match as evidence:

```json
{"type": "cloudtrail", "event_id": "<eventID>", "event_name": "<eventName>", "time": "<eventTime>", "actor": "<userIdentity.arn or unknown>"}
```

When nothing matches, check whether the account has events at all for that period (the earliest
event may be newer than the window: say so in `notes`), and treat the actor as unknown. Changes
made by AWS on the customer's behalf (attachment mapping by policy, Direct Connect maintenance)
often have no customer CloudTrail event. Look for an AWS Health event instead.
