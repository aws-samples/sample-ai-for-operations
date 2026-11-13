# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: AWS regions and their display (long) names.

Primary source: SSM /aws/service/global-infrastructure/regions (account-
independent, covers regions not enabled in the caller's account). Pure code,
no LLM.
"""

from typing import Optional

from strands import tool

from cache import get_or_compute
from tools._common import CONFIDENCE_HIGH, SOURCE_SSM_GLOBAL, ssm_global_client

_REGIONS_PATH = "/aws/service/global-infrastructure/regions"


def _fetch_all_region_codes() -> list[str]:
    client = ssm_global_client()
    codes: list[str] = []
    paginator = client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=_REGIONS_PATH):
        for param in page.get("Parameters", []):
            # name looks like /aws/service/global-infrastructure/regions/us-east-1
            codes.append(param["Name"].rsplit("/", 1)[-1])
    return sorted(codes)


def _fetch_long_name(region: str) -> Optional[str]:
    client = ssm_global_client()
    try:
        resp = client.get_parameter(Name=f"{_REGIONS_PATH}/{region}/longName")
        return resp["Parameter"]["Value"]
    except client.exceptions.ParameterNotFound:
        return None


def resolve_regions_impl(region: Optional[str] = None) -> dict:
    """Core logic (testable without the Strands runtime)."""

    def _compute_one(r: str) -> dict:
        return {
            "regions": [
                {
                    "code": r,
                    "long_name": _fetch_long_name(r),
                    "source": SOURCE_SSM_GLOBAL,
                    "confidence": CONFIDENCE_HIGH,
                }
            ]
        }

    if region:
        region = region.strip()
        return get_or_compute("regions", lambda: _compute_one(region), region=region)

    def _compute_all() -> dict:
        codes = _fetch_all_region_codes()
        return {
            "regions": [
                {
                    "code": c,
                    "long_name": _fetch_long_name(c),
                    "source": SOURCE_SSM_GLOBAL,
                    "confidence": CONFIDENCE_HIGH,
                }
                for c in codes
            ]
        }

    return get_or_compute("regions", _compute_all)


@tool
def resolve_regions(region: Optional[str] = None) -> dict:
    """Return AWS regions and their display (long) names.

    Works for regions NOT enabled in the caller's account (sourced from SSM
    global-infrastructure public parameters).

    Args:
        region: optional single region code (e.g. "eu-south-2"). If omitted,
            returns all known regions.

    Returns:
        {"regions": [{"code", "long_name", "source", "confidence"}, ...]}
    """
    return resolve_regions_impl(region)
