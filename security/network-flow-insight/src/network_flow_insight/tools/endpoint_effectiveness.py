# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: private endpoints that exist but are not carrying their service's traffic.

Three findings, each with the resource and the volume:
(1) an interface endpoint exists in a VPC and that service's prefixes still appear on the NAT path;
(2) a subnet has no gateway-endpoint route and its S3 or DynamoDB traffic crosses NAT;
(3) S3 or DynamoDB in another Region crosses NAT (no gateway endpoint can reach it).
"""

from __future__ import annotations

from collections import defaultdict

from ..core.inventory import Inventory
from .classify_destination import short_service

GATEWAY_SERVICES = ("S3", "DYNAMODB")


def endpoint_effectiveness(enriched: list[dict], inventory: Inventory | None) -> dict:
    if inventory is None:
        return {
            "status": "unavailable",
            "why": "needs endpoints and route tables from an inventory provider",
            "interface_endpoint_findings": [],
            "missing_gateway_route_findings": [],
            "cross_region_findings": [],
        }
    nat = [
        c
        for c in enriched
        if c["path_class"] == "internet-nat" and c["dest_bucket"] == "aws-service" and c.get("egress")
    ]

    # (1) interface endpoints whose service still crosses NAT
    ie: list[dict] = []
    for ep in inventory.endpoints:
        if ep.get("type") != "Interface":
            continue
        svc = short_service(ep["service_name"])
        hits = [c for c in nat if c["dest_service"] == svc and c["client_vpc"] == ep["vpc_id"]]
        if not hits:
            continue
        ep_azs = {inventory.subnets[s]["az"] for s in ep.get("subnet_ids", []) if s in inventory.subnets}
        by_subnet: dict[str, int] = defaultdict(int)
        for c in hits:
            by_subnet[c["client_subnet"] or c["consumer"]] += c["total_bytes"]
        causes = []
        if not ep.get("private_dns"):
            causes.append("private DNS is disabled on the endpoint")
        outside = sorted(
            s for s in by_subnet if s in inventory.subnets and inventory.subnets[s]["az"] not in ep_azs
        )
        if outside:
            causes.append(f"consumer subnets in Availability Zones the endpoint does not cover: {outside}")
        if any(c["dest_cross_region"] for c in hits):
            causes.append("some traffic targets another Region, which a Regional endpoint cannot serve")
        if not causes:
            causes.append(
                "clients resolve the public service name (SDK endpoint override, custom resolver or a cached address)"
            )
        ie.append(
            {
                "endpoint_id": ep["id"],
                "service": svc,
                "vpc_id": ep["vpc_id"],
                "bytes_on_nat": sum(c["total_bytes"] for c in hits),
                "by_subnet": dict(sorted(by_subnet.items())),
                "workloads": sorted({c["client"] for c in hits}),
                "private_dns_enabled": bool(ep.get("private_dns")),
                "likely_causes": causes,
            }
        )

    # (2) subnets without a gateway-endpoint route
    gw_services = {
        (e["vpc_id"], short_service(e["service_name"]))
        for e in inventory.endpoints
        if e.get("type") == "Gateway"
    }
    missing: dict[tuple[str, str], dict] = {}
    for c in nat:
        if c["dest_service"] not in GATEWAY_SERVICES or c["dest_cross_region"] or not c["client_subnet"]:
            continue
        route = inventory.route_for(c["client_subnet"], c["server"])
        if route and route["target_type"] == "gateway-endpoint":
            continue
        k = (c["client_subnet"], c["dest_service"])
        m = missing.setdefault(
            k,
            {
                "subnet_id": k[0],
                "service": k[1],
                "bytes_on_nat": 0,
                "workloads": set(),
                "vpc_id": c["client_vpc"],
            },
        )
        m["bytes_on_nat"] += c["total_bytes"]
        m["workloads"].add(c["client"])
    gw_findings = []
    for (_s, _svc), m in sorted(missing.items()):
        m["workloads"] = sorted(m["workloads"])
        m["vpc_has_gateway_endpoint"] = (m["vpc_id"], m["service"]) in gw_services
        m["observation"] = (
            "a gateway endpoint exists in the VPC but this subnet's route table has no route to it"
            if m["vpc_has_gateway_endpoint"]
            else "the VPC has no gateway endpoint for this service"
        )
        gw_findings.append(m)

    # (3) cross-Region S3 / DynamoDB on NAT
    xr: dict[tuple[str, str], dict] = {}
    for c in nat:
        if c["dest_service"] in GATEWAY_SERVICES and c["dest_cross_region"]:
            k = (c["dest_service"], c["dest_region"])
            m = xr.setdefault(
                k, {"service": k[0], "destination_region": k[1], "bytes_on_nat": 0, "workloads": set()}
            )
            m["bytes_on_nat"] += c["total_bytes"]
            m["workloads"].add(c["client"])
    xr_findings = []
    for _k, m in sorted(xr.items()):
        m["workloads"] = sorted(m["workloads"])
        xr_findings.append(m)

    return {
        "status": "available",
        "interface_endpoint_findings": sorted(ie, key=lambda f: (-f["bytes_on_nat"], f["endpoint_id"])),
        "missing_gateway_route_findings": sorted(
            gw_findings, key=lambda f: (-f["bytes_on_nat"], f["subnet_id"])
        ),
        "cross_region_findings": sorted(xr_findings, key=lambda f: (-f["bytes_on_nat"], f["service"])),
    }
