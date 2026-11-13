# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Data-retrieval tool: whether given AWS services are available in a region.

Primary source: SSM /aws/service/global-infrastructure/services/<svc>/regions
(account-independent, works for non-enabled regions). Pure code, no LLM.
"""

from typing import Optional

from strands import tool

from cache import get_or_compute
from tools._common import CONFIDENCE_HIGH, SOURCE_SSM_GLOBAL, require_region, ssm_global_client

_SVC_PATH = "/aws/service/global-infrastructure/services/{service}/regions"
_DEFAULT_SERVICES = ("ec2", "eks")


def _service_regions(service: str) -> set[str]:
    client = ssm_global_client()
    regions: set[str] = set()
    paginator = client.get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=_SVC_PATH.format(service=service)):
        for param in page.get("Parameters", []):
            regions.add(param["Value"])
    return regions


def resolve_service_availability_impl(
    region: str, services: Optional[list[str]] = None
) -> dict:
    """Core logic (testable without the Strands runtime)."""
    region = require_region(region)
    svc_list = [s.strip().lower() for s in (services or _DEFAULT_SERVICES) if s and s.strip()]

    def _compute() -> dict:
        availability = {svc: (region in _service_regions(svc)) for svc in svc_list}
        return {
            "region": region,
            "services": availability,
            "source": SOURCE_SSM_GLOBAL,
            "confidence": CONFIDENCE_HIGH,
        }

    return get_or_compute(
        "service_availability", _compute, region=region, params={"services": svc_list}
    )


@tool
def resolve_service_availability(region: str, services: Optional[list[str]] = None) -> dict:
    """Return whether AWS services (default Amazon EC2 and Amazon EKS) are
    available in a region.

    Works for regions not enabled in the caller's account (SSM global-
    infrastructure).

    Args:
        region: region code (e.g. "ap-southeast-7").
        services: optional list of service codes (default ["ec2", "eks"]).

    Returns:
        {"region", "services": {"ec2": bool, "eks": bool}, "source", "confidence"}
    """
    return resolve_service_availability_impl(region, services)
