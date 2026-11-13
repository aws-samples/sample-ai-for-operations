# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: availability zones for a region.

Primary source: SSM /aws/service/global-infrastructure/regions/<r>/
availability-zones -> returns AZ IDs, account-independent, works for
non-enabled regions.

Enrichment: when the region is enabled and reachable, a live
ec2:DescribeAvailabilityZones adds human AZ *names*.

When names cannot be obtained (region not enabled), ONLY AZ IDs are returned
and az_names_available is False. AZ names are never fabricated. Pure code, no LLM.
"""

from typing import Optional

from strands import tool

from cache import get_or_compute
from tools._common import (
    CONFIDENCE_HIGH,
    SOURCE_EC2_LIVE,
    SOURCE_SSM_GLOBAL,
    ec2_client,
    require_region,
    ssm_global_client,
)
from tools._resilience import try_live

_AZ_PATH = "/aws/service/global-infrastructure/regions/{region}/availability-zones"


def _fetch_az_ids(region: str) -> list[str]:
    client = ssm_global_client()
    az_ids: list[str] = []
    paginator = client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=_AZ_PATH.format(region=region)):
        for param in page.get("Parameters", []):
            az_ids.append(param["Name"].rsplit("/", 1)[-1])
    return sorted(az_ids)


def _fetch_live_names(region: str) -> Optional[dict[str, str]]:
    """Map az_id -> az_name via a live call, or None if unavailable."""

    def _call() -> dict[str, str]:
        resp = ec2_client(region).describe_availability_zones(
            AllAvailabilityZones=True
        )
        return {
            z["ZoneId"]: z["ZoneName"]
            for z in resp.get("AvailabilityZones", [])
            if z.get("ZoneId")
        }

    return try_live(_call, dataset="availability_zones", region=region)


def resolve_availability_zones_impl(region: str) -> dict:
    """Core logic (testable without the Strands runtime)."""
    region = require_region(region)

    def _compute() -> dict:
        az_ids = _fetch_az_ids(region)
        names = _fetch_live_names(region)
        if names:
            azs = [
                {"az_id": az_id, "az_name": names.get(az_id)}
                for az_id in az_ids
            ]
            return {
                "region": region,
                "azs": azs,
                "az_names_available": True,
                "source": SOURCE_EC2_LIVE,
                "confidence": CONFIDENCE_HIGH,
            }
        # names unavailable -> IDs only, never fabricate a/b/c
        return {
            "region": region,
            "azs": [{"az_id": az_id} for az_id in az_ids],
            "az_names_available": False,
            "source": SOURCE_SSM_GLOBAL,
            "confidence": CONFIDENCE_HIGH,
        }

    return get_or_compute("availability_zones", _compute, region=region)


@tool
def resolve_availability_zones(region: str) -> dict:
    """Return availability zones for a region.

    Always returns AZ IDs (from SSM global-infrastructure, works for regions not
    enabled in the caller's account). When the region is enabled and reachable,
    human AZ names are added and az_names_available is true. When names are
    unavailable, only AZ IDs are returned and az_names_available is false — AZ
    names are never guessed.

    Args:
        region: region code (e.g. "me-south-1").

    Returns:
        {"region", "azs": [{"az_id", "az_name"?}], "az_names_available",
         "source", "confidence"}
    """
    return resolve_availability_zones_impl(region)
