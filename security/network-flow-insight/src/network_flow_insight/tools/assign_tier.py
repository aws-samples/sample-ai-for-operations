# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: capability tier from the fields present and the inventory provider available."""

from __future__ import annotations

from ..core.tablescheme import DEFAULT_FIELDS, ENHANCED_FIELDS, FULL_FIELDS

TIERS = ("basic-no-inventory", "basic-with-inventory", "enhanced", "full")

FORMAT_STRING = (
    "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} "
    "${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${az-id} "
    "${flow-direction} ${pkt-srcaddr} ${pkt-dstaddr} ${traffic-path} ${pkt-src-aws-service} "
    "${pkt-dst-aws-service} ${region}"
)

# section -> {tier: (status, method)} ; status is available | inferred | unavailable
_SECTIONS: dict[str, dict[str, tuple[str, str]]] = {
    "coverage_integrity": {t: ("available", "partitions vs S3 prefixes; log-status shares") for t in TIERS},
    "path_volume": {
        "basic-no-inventory": (
            "inferred",
            "forwarding interfaces detected from the data; NAT, gateway endpoint and internet gateway paths cannot be separated without route tables",
        ),
        "basic-with-inventory": ("available", "interface role, then route table"),
        "enhanced": (
            "available",
            "interface role, then route table; vpc-id, subnet-id and az-id read from the record",
        ),
        "full": ("available", "traffic-path read from the record; inventory is a cross-check"),
    },
    "nat_scoped_analysis": {
        "basic-no-inventory": ("inferred", "NAT gateway interface and addresses inferred from the data"),
        "basic-with-inventory": (
            "available",
            "NAT gateway interfaces and all private addresses from inventory",
        ),
        "enhanced": (
            "available",
            "NAT scoping from inventory; original addresses from pkt-srcaddr and pkt-dstaddr",
        ),
        "full": (
            "available",
            "NAT scoping from inventory; original addresses from pkt-srcaddr and pkt-dstaddr",
        ),
    },
    "nat_workload_attribution": {
        "basic-no-inventory": (
            "inferred",
            "workload addresses from the untranslated leg of an inferred NAT interface; no subnet names",
        ),
        "basic-with-inventory": ("available", "untranslated leg (workload to NAT address), joined to subnets"),
        "enhanced": ("available", "untranslated leg; the real remote from pkt-srcaddr and pkt-dstaddr"),
        "full": ("available", "untranslated leg; the real remote from pkt-srcaddr and pkt-dstaddr"),
    },
    "destination_classification": {
        "basic-no-inventory": ("inferred", "CIDR match against AWS ranges and named networks only"),
        "basic-with-inventory": ("available", "VPC CIDRs, named networks, ip-ranges.json, prefix lists"),
        "enhanced": ("available", "VPC CIDRs, named networks, ip-ranges.json, prefix lists"),
        "full": ("available", "service name from pkt-src/dst-aws-service; ranges as cross-check"),
    },
    "aws_service_reach": {
        "basic-no-inventory": (
            "inferred",
            "S3 and DynamoDB over NAT cannot be told from gateway-endpoint traffic",
        ),
        "basic-with-inventory": (
            "available",
            "route tables separate gateway endpoint, interface endpoint and NAT",
        ),
        "enhanced": ("available", "route tables separate gateway endpoint, interface endpoint and NAT"),
        "full": ("available", "traffic-path and aws-service fields"),
    },
    "endpoint_effectiveness": {
        "basic-no-inventory": ("unavailable", "needs endpoints and route tables from an inventory provider"),
        "basic-with-inventory": ("available", "endpoints and route tables from inventory"),
        "enhanced": ("available", "endpoints and route tables from inventory"),
        "full": ("available", "endpoints and route tables from inventory"),
    },
    "inter_vpc_cross_region": {
        "basic-no-inventory": ("inferred", "private-to-private traffic only; VPC names and Regions unknown"),
        "basic-with-inventory": ("available", "VPC CIDRs and Regions from inventory"),
        "enhanced": ("available", "VPC CIDRs and Regions from inventory"),
        "full": ("available", "traffic-path and inventory"),
    },
    "concentration_time_change": {t: ("available", "aggregate") for t in TIERS},
    "gateway_inventory": {
        "basic-no-inventory": (
            "inferred",
            "gateways detected from the data; idle or unlogged gateways cannot be listed",
        ),
        "basic-with-inventory": ("available", "NAT gateways from inventory with window bytes"),
        "enhanced": ("available", "NAT gateways from inventory with window bytes"),
        "full": ("available", "NAT gateways from inventory with window bytes"),
    },
    "rejected_flows": {t: ("available", "action = REJECT") for t in TIERS},
    "dependency_view": {
        "basic-no-inventory": ("inferred", "groups are /24 networks, not named resources"),
        "basic-with-inventory": ("available", "subnets and VPCs from inventory"),
        "enhanced": ("available", "subnets and VPCs from inventory"),
        "full": ("available", "subnets and VPCs from inventory"),
    },
    "reconciliation": {t: ("available", "leg check always; further rungs when reachable") for t in TIERS},
    "options": {t: ("available", "evidence and published rates; no ranking") for t in TIERS},
}


def _missing(fields: set[str], wanted: tuple[str, ...]) -> list[str]:
    return [f for f in wanted if f not in fields]


def assign_tier(fields: list[str], provider: str) -> dict:
    """Assign the capability tier.

    ``fields`` are the flow-log fields of the table (underscore names); ``provider`` is the inventory
    provider letter (``A`` EC2, ``B`` Config aggregator, ``C`` file, ``D`` none).
    """
    have = set(fields)
    missing_default = _missing(have, DEFAULT_FIELDS)
    if missing_default:
        return {
            "error": f"table is missing required default fields: {missing_default}",
            "tier": None,
        }
    has_inventory = provider in ("A", "B", "C")
    enhanced = not _missing(have, ENHANCED_FIELDS)
    full = enhanced and not _missing(have, FULL_FIELDS)
    if full:
        tier = "full"
    elif enhanced:
        tier = "enhanced"
    else:
        tier = "basic-with-inventory" if has_inventory else "basic-no-inventory"
    sections = {
        name: {"status": by_tier[tier][0], "method": by_tier[tier][1]} for name, by_tier in _SECTIONS.items()
    }
    if not has_inventory and tier in ("enhanced", "full"):
        # Richer fields help, but without an inventory the gateways themselves are still inferred.
        no_inv = {
            "endpoint_effectiveness": (
                "unavailable",
                "needs endpoints and route tables from an inventory provider",
            ),
            "gateway_inventory": (
                "inferred",
                "gateways detected from the data; idle or unlogged gateways cannot be listed",
            ),
            "nat_scoped_analysis": ("inferred", "NAT gateway interface and addresses inferred from the data"),
            "inter_vpc_cross_region": (
                "inferred",
                "VPC names and Regions unknown; private-to-private traffic grouped by network",
            ),
            "dependency_view": (
                "inferred",
                "groups are /24 networks or subnets read from the record, not named resources",
            ),
        }
        if tier == "enhanced":
            no_inv["path_volume"] = (
                "inferred",
                "vpc-id, subnet-id and az-id from the record; NAT, gateway endpoint and internet gateway paths cannot be separated without route tables",
            )
            no_inv["aws_service_reach"] = (
                "inferred",
                "S3 and DynamoDB over NAT cannot be told from gateway-endpoint traffic",
            )
        else:
            no_inv["path_volume"] = ("available", "traffic-path read from the record")
        for k, (status, method) in no_inv.items():
            sections[k] = {"status": status, "method": method}
    unavailable = sorted(k for k, v in sections.items() if v["status"] == "unavailable")
    inferred = sorted(k for k, v in sections.items() if v["status"] == "inferred")
    recommendation = None
    if tier != "full":
        gaps = _missing(have, FULL_FIELDS + ENHANCED_FIELDS)
        recommendation = {
            "custom_format": FORMAT_STRING,
            "missing_fields": sorted(set(gaps)),
            "delivery_options": "Parquet, Hive-compatible prefixes and hourly partitions when the flow log is next recreated; Parquet cuts scanned bytes substantially for the same records.",
            "sections_that_gain_confidence": sorted(set(unavailable + inferred)),
            "inventory_hint": None
            if has_inventory
            else "supply an inventory (provider A, B or C); scripts/collect_inventory.py produces provider C",
        }
    return {
        "tier": tier,
        "provider": provider,
        "sections": sections,
        "available_sections": sorted(k for k, v in sections.items() if v["status"] == "available"),
        "inferred_sections": inferred,
        "unavailable_sections": unavailable,
        "upgrade_recommendation": recommendation,
    }
