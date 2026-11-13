# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: whether instance types are offered in a region.

Primary source: AWS Price List API (a type appearing in get_products for a
region implies it is offered there) -> works for regions not enabled.

Enrichment: live ec2:DescribeInstanceTypeOfferings when the region is enabled.

Pure code, no LLM.
"""

import json
from typing import Optional

from strands import tool

from cache import get_or_compute
from tools._common import (
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    SOURCE_EC2_LIVE,
    SOURCE_PRICING,
    ec2_client,
    pricing_client,
    require_region,
)
from tools._resilience import try_live


def _pricing_offered(region: str, instance_type: Optional[str]) -> set[str]:
    client = pricing_client()
    offered: set[str] = set()
    filters = [
        {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
        {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
        {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
        {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
    ]
    if instance_type:
        filters.append(
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type}
        )
    paginator = client.get_paginator("get_products")
    for page in paginator.paginate(ServiceCode="AmazonEC2", Filters=filters):
        for raw in page.get("PriceList", []):
            attrs = json.loads(raw).get("product", {}).get("attributes", {})
            it = attrs.get("instanceType")
            if it:
                offered.add(it)
    return offered


def _live_offered(region: str, instance_type: Optional[str]) -> Optional[set[str]]:
    def _call() -> set[str]:
        client = ec2_client(region)
        offered: set[str] = set()
        kwargs = {"LocationType": "region"}
        if instance_type:
            kwargs["Filters"] = [
                {"Name": "instance-type", "Values": [instance_type]}
            ]
        paginator = client.get_paginator("describe_instance_type_offerings")
        for page in paginator.paginate(**kwargs):
            for off in page.get("InstanceTypeOfferings", []):
                offered.add(off["InstanceType"])
        return offered

    return try_live(_call, dataset="instance_offerings", region=region)


def resolve_instance_offerings_impl(
    region: str, instance_type: Optional[str] = None
) -> dict:
    """Core logic (testable without the Strands runtime)."""
    region = require_region(region)
    itype = (
        instance_type.strip()
        if isinstance(instance_type, str) and instance_type.strip()
        else None
    )

    def _compute() -> dict:
        live = _live_offered(region, itype)
        if live is not None:
            source, confidence, offered = SOURCE_EC2_LIVE, CONFIDENCE_HIGH, live
        else:
            source, confidence, offered = (
                SOURCE_PRICING,
                CONFIDENCE_MEDIUM,
                _pricing_offered(region, itype),
            )
        if itype:
            return {
                "region": region,
                "offerings": [
                    {"instance_type": itype, "offered": itype in offered,
                     "source": source, "confidence": confidence}
                ],
            }
        return {
            "region": region,
            "offerings": [
                {"instance_type": t, "offered": True, "source": source,
                 "confidence": confidence}
                for t in sorted(offered)
            ],
        }

    return get_or_compute(
        "instance_offerings", _compute, region=region, params={"instance_type": itype}
    )


@tool
def resolve_instance_offerings(region: str, instance_type: Optional[str] = None) -> dict:
    """Return which instance types are offered in a region.

    Uses the AWS Price List API (works for regions not enabled) and enriches with
    live Amazon EC2 describe-instance-type-offerings when the region is enabled.

    Args:
        region: region code.
        instance_type: optional single type to check (e.g. "m6i.large").

    Returns:
        {"region", "offerings": [{"instance_type","offered","source",
         "confidence"}, ...]}
    """
    return resolve_instance_offerings_impl(region, instance_type)
