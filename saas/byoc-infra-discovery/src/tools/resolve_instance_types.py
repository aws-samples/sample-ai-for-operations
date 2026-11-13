# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: instance-type attributes for a region.

Primary source: AWS Price List API get_products (regionCode filter) -> works for
regions NOT enabled in the caller's account, but processor architecture is coarse
("64-bit") and storage is free text.

Enrichment: live ec2:DescribeInstanceTypes when the region is enabled -> precise
architecture and local-storage attributes.

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


def _pricing_instance_types(region: str, family: Optional[str]) -> list[dict]:
    client = pricing_client()
    results: dict[str, dict] = {}
    paginator = client.get_paginator("get_products")
    filters = [
        {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
        {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
        {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
        {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
    ]
    for page in paginator.paginate(ServiceCode="AmazonEC2", Filters=filters):
        for raw in page.get("PriceList", []):
            attrs = json.loads(raw).get("product", {}).get("attributes", {})
            itype = attrs.get("instanceType")
            if not itype or itype in results:
                continue
            if family and not itype.startswith(family):
                continue
            results[itype] = {
                "name": itype,
                "vcpu": _to_int(attrs.get("vcpu")),
                "memory_mib": _mem_to_mib(attrs.get("memory")),
                "processor": attrs.get("physicalProcessor"),
                "arch": None,  # Pricing arch is coarse; left for live enrichment
                "local_storage": attrs.get("storage"),
                "source": SOURCE_PRICING,
                "confidence": CONFIDENCE_MEDIUM,
            }
    return sorted(results.values(), key=lambda x: x["name"])


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _mem_to_mib(value: Optional[str]) -> Optional[int]:
    # Pricing memory looks like "8 GiB"
    if not value:
        return None
    try:
        num = float(str(value).split()[0].replace(",", ""))
        return int(num * 1024)
    except (ValueError, IndexError):
        return None


def _live_enrich(region: str, family: Optional[str]) -> Optional[list[dict]]:
    def _call() -> list[dict]:
        client = ec2_client(region)
        out: list[dict] = []
        paginator = client.get_paginator("describe_instance_types")
        for page in paginator.paginate():
            for it in page.get("InstanceTypes", []):
                name = it["InstanceType"]
                if family and not name.startswith(family):
                    continue
                vcpu = it.get("VCpuInfo", {}).get("DefaultVCpus")
                mem = it.get("MemoryInfo", {}).get("SizeInMiB")
                archs = it.get("ProcessorInfo", {}).get("SupportedArchitectures", [])
                storage = None
                if it.get("InstanceStorageSupported"):
                    storage = it.get("InstanceStorageInfo", {}).get("TotalSizeInGB")
                out.append(
                    {
                        "name": name,
                        "vcpu": vcpu,
                        "memory_mib": mem,
                        "processor": it.get("ProcessorInfo", {}).get(
                            "SupportedArchitectures", [None]
                        )[0],
                        "arch": archs[0] if archs else None,
                        "local_storage": storage,
                        "source": SOURCE_EC2_LIVE,
                        "confidence": CONFIDENCE_HIGH,
                    }
                )
        return sorted(out, key=lambda x: x["name"])

    return try_live(_call, dataset="instance_types", region=region)


def resolve_instance_types_impl(region: str, family: Optional[str] = None) -> dict:
    """Core logic (testable without the Strands runtime)."""
    region = require_region(region)
    fam = family.strip() if isinstance(family, str) and family.strip() else None

    def _compute() -> dict:
        live = _live_enrich(region, fam)
        if live is not None:
            return {"region": region, "instance_types": live}
        pricing = _pricing_instance_types(region, fam)
        return {"region": region, "instance_types": pricing}

    return get_or_compute(
        "instance_types", _compute, region=region, params={"family": fam}
    )


@tool
def resolve_instance_types(region: str, family: Optional[str] = None) -> dict:
    """Return instance-type attributes (vCPU, memory, processor, arch, local
    storage) for a region.

    Uses the AWS Price List API (works for regions not enabled in the caller's
    account, coarse architecture) and enriches with live Amazon EC2 data when the
    region is enabled (precise architecture and local storage).

    Args:
        region: region code.
        family: optional instance family prefix filter (e.g. "m6i").

    Returns:
        {"region", "instance_types": [{"name","vcpu","memory_mib","processor",
         "arch","local_storage","source","confidence"}, ...]}
    """
    return resolve_instance_types_impl(region, family)
