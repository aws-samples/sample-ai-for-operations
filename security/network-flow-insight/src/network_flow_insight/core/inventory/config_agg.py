# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Provider B: build the inventory document from an AWS Config aggregator.

Uses ``SelectAggregateResourceConfig`` only. AWS Config stores the configuration of most EC2 network
resources in the same shape as the EC2 ``Describe*`` responses with the first letter of every key in
lower case, so the key casing is restored and the provider-A mapping functions are reused.

Known limitation: AWS-managed and customer-managed prefix lists are not recorded here, so a route
that targets a prefix list (the usual form of a gateway-endpoint route) is recognised by its target
but its CIDRs are empty. Path classification then reports those flows with method ``inferred`` where
the destination matches the S3 or DynamoDB ranges. Provider A or C carries full prefix-list entries.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from .ec2 import SCHEMA_VERSION, eni_role, route_target

RESOURCE_TYPES = (
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::RouteTable",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::NatGateway",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::TransitGatewayAttachment",
)


def _pascal(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {(k[:1].upper() + k[1:]): _pascal(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_pascal(v) for v in obj]
    return obj


def _query(client: Any, aggregator: str) -> list[dict]:
    types = ", ".join(f"'{t}'" for t in RESOURCE_TYPES)
    expr = (
        "SELECT resourceId, resourceType, accountId, awsRegion, configuration "
        f"WHERE resourceType IN ({types})"
    )
    rows: list[dict] = []
    token = None
    while True:
        kw: dict[str, Any] = {"Expression": expr, "ConfigurationAggregatorName": aggregator, "Limit": 100}
        if token:
            kw["NextToken"] = token
        page = client.select_aggregate_resource_config(**kw)
        for r in page.get("Results", []):
            rows.append(json.loads(r))
        token = page.get("NextToken")
        if not token:
            return rows


def collect(config_client: Any, aggregator: str) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": "config",
        "collected_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vpcs": [],
        "subnets": [],
        "route_tables": [],
        "interfaces": [],
        "nat_gateways": [],
        "endpoints": [],
        "prefix_lists": [],
        "tgw_attachments": [],
    }
    rts_raw: list[tuple[dict, dict]] = []
    for row in _query(config_client, aggregator):
        t = row["resourceType"]
        acct, region, rid = row["accountId"], row["awsRegion"], row["resourceId"]
        c = _pascal(row.get("configuration") or {})
        if t == "AWS::EC2::VPC":
            cidrs = [a["CidrBlock"] for a in c.get("CidrBlockAssociationSet", []) if a.get("CidrBlock")]
            doc["vpcs"].append(
                {"id": rid, "account_id": acct, "region": region, "cidrs": cidrs or [c.get("CidrBlock", "")]}
            )
        elif t == "AWS::EC2::Subnet":
            doc["subnets"].append(
                {
                    "id": rid,
                    "vpc_id": c.get("VpcId", ""),
                    "account_id": acct,
                    "region": region,
                    "az": c.get("AvailabilityZoneId") or c.get("AvailabilityZone", ""),
                    "cidr": c.get("CidrBlock", ""),
                    "route_table_id": "",
                }
            )
        elif t == "AWS::EC2::RouteTable":
            rts_raw.append((row, c))
        elif t == "AWS::EC2::NetworkInterface":
            doc["interfaces"].append(
                {
                    "id": rid,
                    "account_id": acct,
                    "region": region,
                    "vpc_id": c.get("VpcId", ""),
                    "subnet_id": c.get("SubnetId", ""),
                    "az": c.get("AvailabilityZone", ""),
                    "role": eni_role(c),
                    "private_ips": [p["PrivateIpAddress"] for p in c.get("PrivateIpAddresses", [])],
                    "description": c.get("Description", ""),
                }
            )
        elif t == "AWS::EC2::NatGateway":
            if c.get("State") not in (None, "available", "pending"):
                continue
            addrs = c.get("NatGatewayAddresses", [])
            doc["nat_gateways"].append(
                {
                    "id": rid,
                    "vpc_id": c.get("VpcId", ""),
                    "subnet_id": c.get("SubnetId", ""),
                    "interface_ids": sorted(
                        {a["NetworkInterfaceId"] for a in addrs if a.get("NetworkInterfaceId")}
                    ),
                    "private_ips": sorted({a["PrivateIp"] for a in addrs if a.get("PrivateIp")}),
                    "public_ips": sorted({a["PublicIp"] for a in addrs if a.get("PublicIp")}),
                }
            )
        elif t == "AWS::EC2::VPCEndpoint":
            doc["endpoints"].append(
                {
                    "id": rid,
                    "vpc_id": c.get("VpcId", ""),
                    "type": c.get("VpcEndpointType", "Interface"),
                    "service_name": c.get("ServiceName", ""),
                    "subnet_ids": c.get("SubnetIds", []),
                    "interface_ids": c.get("NetworkInterfaceIds", []),
                    "private_dns": bool(c.get("PrivateDnsEnabled")),
                }
            )
        elif t == "AWS::EC2::TransitGatewayAttachment":
            doc["tgw_attachments"].append(
                {
                    "id": rid,
                    "transit_gateway_id": c.get("TransitGatewayId", ""),
                    "vpc_id": c.get("ResourceId", "") if c.get("ResourceType") == "vpc" else "",
                    "resource_type": c.get("ResourceType", ""),
                    "interface_ids": [],
                }
            )
    subnet_rt: dict[str, str] = {}
    main_by_vpc: dict[str, str] = {}
    for row, c in rts_raw:
        main = False
        routes = []
        for a in c.get("Associations", []):
            if a.get("Main"):
                main = True
                main_by_vpc[c.get("VpcId", "")] = row["resourceId"]
            if a.get("SubnetId"):
                subnet_rt[a["SubnetId"]] = row["resourceId"]
        for r in c.get("Routes", []):
            tgt = route_target(r)
            if tgt is None:
                continue
            e: dict[str, Any] = {"target_type": tgt[0], "target_id": tgt[1]}
            if r.get("DestinationCidrBlock"):
                e["destination"] = r["DestinationCidrBlock"]
            elif r.get("DestinationPrefixListId"):
                e["prefix_list_id"] = r["DestinationPrefixListId"]
            else:
                continue
            routes.append(e)
        doc["route_tables"].append(
            {"id": row["resourceId"], "vpc_id": c.get("VpcId", ""), "main": main, "routes": routes}
        )
    for s in doc["subnets"]:
        s["route_table_id"] = subnet_rt.get(s["id"]) or main_by_vpc.get(s["vpc_id"], "")
    return doc
