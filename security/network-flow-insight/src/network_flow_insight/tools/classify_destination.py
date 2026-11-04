# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: classify remote addresses into destination buckets.

Order: the endpoint or VPC that owns the address in inventory, customer-named networks from the
intent file, AWS public ranges (most specific match), customer prefix lists, then the default
taxonomy. An address matching only the generic EC2 or AMAZON ranges is "aws-hosted-unverified",
never an AWS service.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..core.intent_schema import Intent
from ..core.inventory import Inventory
from ..core.ipranges import IpRanges, is_private

BUCKETS = (
    "own-vpc",
    "named-network",
    "aws-service",
    "aws-hosted-unverified",
    "prefix-list",
    "private-unnamed",
    "other-internet",
)


def short_service(service_name: str) -> str:
    """``com.amazonaws.eu-west-2.dynamodb`` -> ``DYNAMODB`` (the ip-ranges.json service key)."""
    return service_name.rsplit(".", 1)[-1].upper().replace("-", "_")


def _networks(intent: Intent | None) -> list[tuple[Any, Any]]:
    if not intent:
        return []
    out = [(ipaddress.ip_network(c, strict=False), nn) for nn in intent.networks for c in nn.cidrs]
    return sorted(out, key=lambda t: t[0].prefixlen, reverse=True)


def _customer_lists(inventory: Inventory | None) -> list[tuple[Any, dict]]:
    if not inventory:
        return []
    out = []
    for pl in inventory.prefix_lists.values():
        if pl.get("name", "").startswith("com.amazonaws."):
            continue
        out += [(ipaddress.ip_network(c, strict=False), pl) for c in pl.get("cidrs", [])]
    return sorted(out, key=lambda t: t[0].prefixlen, reverse=True)


def classify_destination(
    ips: list[str],
    inventory: Inventory | None = None,
    intent: Intent | None = None,
    ranges: IpRanges | None = None,
    *,
    home_region: str = "",
    resolver_names: dict[str, list[str]] | None = None,
) -> dict[str, dict]:
    nets = _networks(intent)
    plists = _customer_lists(inventory)
    endpoint_by_eni: dict[str, dict] = {}
    if inventory:
        for e in inventory.endpoints:
            for eid in e.get("interface_ids", []):
                endpoint_by_eni[eid] = e
    out: dict[str, dict] = {}
    for ip in sorted(set(ips)):
        out[ip] = _one(
            ip, inventory, nets, plists, endpoint_by_eni, ranges, home_region, resolver_names or {}
        )
    return out


def _one(ip, inventory, nets, plists, endpoint_by_eni, ranges, home_region, names) -> dict:
    res: dict[str, Any] = {
        "ip": ip,
        "bucket": "other-internet",
        "service": "",
        "name": "",
        "region": "",
        "cross_region": False,
        "method": "default",
        "detail": "",
    }
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        res.update(bucket="other-internet", method="unparsed", detail="not an IP address")
        return res
    if addr.version != 4:
        res.update(method="unsupported", detail="IPv6 is not classified in v1")
        return res
    if inventory:
        owner = inventory.owner_of_ip(ip)
        if owner and owner["role"] == "interface-endpoint" and owner["id"] in endpoint_by_eni:
            ep = endpoint_by_eni[owner["id"]]
            res.update(
                bucket="aws-service",
                service=short_service(ep["service_name"]),
                name=ep["id"],
                region=owner.get("region", ""),
                method="inventory-endpoint",
                detail=f"interface endpoint {ep['id']}",
            )
            return res
        vpc = inventory.vpc_for_ip(ip)
        if vpc:
            res.update(
                bucket="own-vpc",
                name=vpc["id"],
                region=vpc.get("region", ""),
                cross_region=bool(home_region and vpc.get("region") and vpc["region"] != home_region),
                method="inventory-vpc",
                detail=f"VPC {vpc['id']} in account {vpc.get('account_id', '')}",
            )
            return res
    for net, nn in nets:
        if addr in net:
            res.update(bucket="named-network", name=nn.name, method="intent", detail=f"{nn.kind} {net}")
            res["kind"] = nn.kind
            return res
    if not is_private(ip) and ranges:
        m = ranges.lookup(ip)
        if m:
            region = next((r for r in m.regions if r and r != "GLOBAL"), "")
            if m.specific_services:
                res.update(
                    bucket="aws-service",
                    service=m.specific_services[0],
                    region=region,
                    cross_region=bool(home_region and region and region != home_region),
                    method="ip-ranges",
                    detail=f"{m.cidr} {','.join(m.services)}",
                )
                return res
            res.update(
                bucket="aws-hosted-unverified",
                region=region,
                method="ip-ranges",
                detail=f"{m.cidr} {','.join(m.services)} (generic range)",
            )
            _name(res, ip, names)
            return res
    for net, pl in plists:
        if addr in net:
            res.update(bucket="prefix-list", name=pl["name"], method="prefix-list", detail=pl["id"])
            return res
    if is_private(ip):
        res.update(
            bucket="private-unnamed",
            method="default",
            detail="private address outside any known VPC or named network",
        )
        return res
    _name(res, ip, names)
    return res


def _name(res: dict, ip: str, names: dict[str, list[str]]) -> None:
    if names.get(ip):
        res["name"] = names[ip][0]
        res["method"] += "+resolver"
        res["detail"] += f" resolver: {', '.join(names[ip][:3])}"


def bucket_for(classification: dict, path_class: str, intent: Intent | None) -> dict:
    """Apply the customer's bucket taxonomy (intent file) to one classified destination."""
    if not intent or not intent.buckets:
        return {"bucket": classification["bucket"], "disposition": None, "custom": False}
    for b in intent.buckets:
        m = b.match
        if m.default:
            continue
        if m.services and classification["service"] not in m.services:
            continue
        if m.paths and path_class not in m.paths and _short_path(path_class) not in m.paths:
            continue
        if m.classes and classification["bucket"] not in m.classes:
            continue
        if m.networks and classification["name"] not in m.networks:
            continue
        if m.aws_service is not None and (classification["bucket"] == "aws-service") != m.aws_service:
            continue
        return {"bucket": b.name, "disposition": b.disposition, "custom": True}
    for b in intent.buckets:
        if b.match.default:
            return {"bucket": b.name, "disposition": b.disposition, "custom": True}
    return {"bucket": classification["bucket"], "disposition": None, "custom": False}


def _short_path(path_class: str) -> str:
    return {
        "internet-nat": "nat",
        "gateway-endpoint": "gateway-endpoint",
        "interface-endpoint": "interface-endpoint",
    }.get(path_class, path_class)
