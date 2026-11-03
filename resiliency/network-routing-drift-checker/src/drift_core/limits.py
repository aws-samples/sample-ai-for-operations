# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 5 limit registry (requirements §5.1, design.md D§4.5).

Static limits are the documented defaults, verified at spec time. Customers with a raised
quota override the threshold per limit (LIMIT_THRESHOLD_OVERRIDES) or edit this registry.
"""

from __future__ import annotations

from dataclasses import dataclass

DX_QUOTAS_URL = "https://docs.aws.amazon.com/directconnect/latest/UserGuide/limits.html"
TGW_QUOTAS_URL = "https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-quotas.html"
CLOUDWAN_QUOTAS_URL = "https://docs.aws.amazon.com/vpc/latest/cloudwan/cloudwan-quotas.html"


@dataclass(frozen=True)
class Limit:
    name: str
    description: str
    scope: str
    limit_source: str  # "configured" (read from the resource) | "static"
    default_limit: int
    doc_url: str
    approximate: bool = False


ONPREM_TO_AWS_PER_VIF = Limit(
    name="dx-onprem-to-aws-per-bgp-session",
    description="Routes advertised from on-premises to AWS per BGP session (per address family)",
    scope="transit VIF",
    limit_source="configured",
    default_limit=100,
    doc_url=DX_QUOTAS_URL,
    approximate=True,
)
TGW_TO_ONPREM_PER_ASSOCIATION = Limit(
    name="dx-tgw-to-onprem-prefixes",
    description="Prefixes advertised from a transit gateway to on-premises over a transit VIF (IPv4 + IPv6 combined)",
    scope="DX gateway to transit gateway association",
    limit_source="static",
    default_limit=200,
    doc_url=DX_QUOTAS_URL,
)
CLOUDWAN_TO_ONPREM_PER_DXGW = Limit(
    name="dx-cloudwan-to-onprem-prefixes",
    description="Route prefixes advertised from a Cloud WAN core network DX gateway attachment to on-premises",
    scope="DX gateway attachment",
    limit_source="static",
    default_limit=5000,
    doc_url=DX_QUOTAS_URL,
)
TGW_TOTAL_ROUTES = Limit(
    name="tgw-total-routes",
    description="Total combined routes (dynamic and static) across all route tables of one transit gateway",
    scope="transit gateway",
    limit_source="static",
    default_limit=10000,
    doc_url=TGW_QUOTAS_URL,
)
CLOUDWAN_TOTAL_ROUTES = Limit(
    name="cloudwan-total-routes",
    description="Routes per core network, across all segments",
    scope="core network",
    limit_source="static",
    default_limit=10000,
    doc_url=CLOUDWAN_QUOTAS_URL,
)

REGISTRY: tuple[Limit, ...] = (
    ONPREM_TO_AWS_PER_VIF,
    TGW_TO_ONPREM_PER_ASSOCIATION,
    CLOUDWAN_TO_ONPREM_PER_DXGW,
    TGW_TOTAL_ROUTES,
    CLOUDWAN_TOTAL_ROUTES,
)


def threshold_for(limit: Limit, default_pct: float, overrides: dict[str, float]) -> float:
    return overrides.get(limit.name, default_pct)


def percent(count: int, limit: int) -> float:
    """Exact percentage rounded to one decimal; limit <= 0 is treated as 100 %."""
    if limit <= 0:
        return 100.0
    return round(count * 100.0 / limit, 1)
