# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Provider A: collect the inventory document from Amazon EC2 in one account.

Read-only ``describe-*`` calls only. This module depends on the standard library and boto3 alone and
has no package-relative imports, so ``scripts/collect_inventory.py`` can load it from a clone of the
repository without installing anything else. Provider C is the JSON this module emits.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

SCHEMA_VERSION = 1


def _paginate(client: Any, op: str, key: str, **kw: Any) -> list[dict]:
    out: list[dict] = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


def eni_role(eni: dict) -> str:
    itype = (eni.get("InterfaceType") or "interface").lower()
    desc = eni.get("Description") or ""
    if itype in ("nat_gateway", "natgateway"):
        return "nat-gateway"
    if itype in ("vpc_endpoint", "gateway_load_balancer_endpoint"):
        return "interface-endpoint"
    if itype == "transit_gateway":
        return "transit-gateway"
    if itype in ("network_load_balancer", "gateway_load_balancer") or desc.startswith("ELB "):
        return "load-balancer"
    if itype in ("interface", "efa", "lambda", "trunk"):
        return "workload"
    return "other"


def route_target(route: dict) -> tuple[str, str] | None:
    if route.get("State") == "blackhole":
        return None
    gw = route.get("GatewayId") or ""
    if route.get("NatGatewayId"):
        return "nat-gateway", route["NatGatewayId"]
    if route.get("TransitGatewayId"):
        return "transit-gateway", route["TransitGatewayId"]
    if route.get("VpcPeeringConnectionId"):
        return "peering", route["VpcPeeringConnectionId"]
    if route.get("NetworkInterfaceId"):
        return "network-interface", route["NetworkInterfaceId"]
    if gw == "local":
        return "local", "local"
    if gw.startswith("igw-"):
        return "internet-gateway", gw
    if gw.startswith("vgw-"):
        return "vgw", gw
    if gw.startswith("vpce-"):
        return "gateway-endpoint", gw
    return "other", gw or route.get("CarrierGatewayId", "") or route.get("EgressOnlyInternetGatewayId", "")


def collect_region(ec2: Any, region: str, account_id: str) -> dict[str, list]:
    vpcs = [
        {
            "id": v["VpcId"],
            "account_id": account_id,
            "region": region,
            "cidrs": [
                a["CidrBlock"]
                for a in v.get("CidrBlockAssociationSet", [])
                if a.get("CidrBlockState", {}).get("State") == "associated"
            ]
            or [v["CidrBlock"]],
        }
        for v in _paginate(ec2, "describe_vpcs", "Vpcs")
    ]
    raw_rts = _paginate(ec2, "describe_route_tables", "RouteTables")
    subnet_rt: dict[str, str] = {}
    route_tables = []
    for rt in raw_rts:
        main = False
        for a in rt.get("Associations", []):
            if a.get("Main"):
                main = True
            if a.get("SubnetId"):
                subnet_rt[a["SubnetId"]] = rt["RouteTableId"]
        routes = []
        for r in rt.get("Routes", []):
            tgt = route_target(r)
            if tgt is None:
                continue
            entry: dict[str, Any] = {"target_type": tgt[0], "target_id": tgt[1]}
            if r.get("DestinationCidrBlock"):
                entry["destination"] = r["DestinationCidrBlock"]
            elif r.get("DestinationPrefixListId"):
                entry["prefix_list_id"] = r["DestinationPrefixListId"]
            else:
                continue  # IPv6 and other destinations are out of scope in v1
            routes.append(entry)
        route_tables.append({"id": rt["RouteTableId"], "vpc_id": rt["VpcId"], "main": main, "routes": routes})
    main_by_vpc = {rt["vpc_id"]: rt["id"] for rt in route_tables if rt["main"]}
    subnets = []
    for s in _paginate(ec2, "describe_subnets", "Subnets"):
        subnets.append(
            {
                "id": s["SubnetId"],
                "vpc_id": s["VpcId"],
                "account_id": account_id,
                "region": region,
                "az": s.get("AvailabilityZoneId") or s["AvailabilityZone"],
                "cidr": s["CidrBlock"],
                "route_table_id": subnet_rt.get(s["SubnetId"]) or main_by_vpc.get(s["VpcId"], ""),
            }
        )
    interfaces = []
    for e in _paginate(ec2, "describe_network_interfaces", "NetworkInterfaces"):
        interfaces.append(
            {
                "id": e["NetworkInterfaceId"],
                "account_id": account_id,
                "region": region,
                "vpc_id": e.get("VpcId", ""),
                "subnet_id": e.get("SubnetId", ""),
                "az": e.get("AvailabilityZone", ""),
                "role": eni_role(e),
                "private_ips": [p["PrivateIpAddress"] for p in e.get("PrivateIpAddresses", [])],
                "description": e.get("Description", ""),
            }
        )
    nat_gateways = []
    for n in _paginate(ec2, "describe_nat_gateways", "NatGateways"):
        if n.get("State") not in ("available", "pending"):
            continue
        addrs = n.get("NatGatewayAddresses", [])
        nat_gateways.append(
            {
                "id": n["NatGatewayId"],
                "vpc_id": n.get("VpcId", ""),
                "subnet_id": n.get("SubnetId", ""),
                "interface_ids": sorted(
                    {a["NetworkInterfaceId"] for a in addrs if a.get("NetworkInterfaceId")}
                ),
                "private_ips": sorted({a["PrivateIp"] for a in addrs if a.get("PrivateIp")}),
                "public_ips": sorted({a["PublicIp"] for a in addrs if a.get("PublicIp")}),
            }
        )
    endpoints = [
        {
            "id": e["VpcEndpointId"],
            "vpc_id": e["VpcId"],
            "type": e["VpcEndpointType"],
            "service_name": e["ServiceName"],
            "subnet_ids": e.get("SubnetIds", []),
            "interface_ids": e.get("NetworkInterfaceIds", []),
            "private_dns": bool(e.get("PrivateDnsEnabled")),
        }
        for e in _paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints")
        if e.get("State") in ("available", "pending", "pendingAcceptance")
    ]
    prefix_lists = []
    for p in _paginate(ec2, "describe_managed_prefix_lists", "PrefixLists"):
        entries = _paginate(ec2, "get_managed_prefix_list_entries", "Entries", PrefixListId=p["PrefixListId"])
        prefix_lists.append(
            {"id": p["PrefixListId"], "name": p["PrefixListName"], "cidrs": [e["Cidr"] for e in entries]}
        )
    tgw = [
        {
            "id": a["TransitGatewayAttachmentId"],
            "transit_gateway_id": a["TransitGatewayId"],
            "vpc_id": a.get("ResourceId", "") if a.get("ResourceType") == "vpc" else "",
            "resource_type": a.get("ResourceType", ""),
            "interface_ids": [],
        }
        for a in _paginate(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments")
    ]
    return {
        "vpcs": vpcs,
        "subnets": subnets,
        "route_tables": route_tables,
        "interfaces": interfaces,
        "nat_gateways": nat_gateways,
        "endpoints": endpoints,
        "prefix_lists": prefix_lists,
        "tgw_attachments": tgw,
    }


def collect(session: Any, regions: list[str], account_id: str | None = None) -> dict[str, Any]:
    """Collect the inventory document for ``regions`` using a boto3 ``Session``."""
    if account_id is None:
        account_id = session.client("sts").get_caller_identity()["Account"]
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "source": "ec2",
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
    seen_pl: set[str] = set()
    for region in regions:
        part = collect_region(session.client("ec2", region_name=region), region, account_id)
        for k, v in part.items():
            if k == "prefix_lists":
                doc[k] += [p for p in v if p["id"] not in seen_pl]
                seen_pl.update(p["id"] for p in v)
            else:
                doc[k] += v
    return doc
