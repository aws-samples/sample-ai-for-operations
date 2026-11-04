# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: published rates from the AWS Price List API, per Region. Never hard-coded."""

from __future__ import annotations

import json
from typing import Any

# Price List "location" names for commercial Regions.
LOCATIONS = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "sa-east-1": "South America (Sao Paulo)",
    "me-south-1": "Middle East (Bahrain)",
    "af-south-1": "Africa (Cape Town)",
}


def _products(client: Any, service: str, filters: dict[str, str]) -> list[dict]:
    flt = [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in filters.items()]
    out: list[dict] = []
    token = None
    while True:
        kw: dict[str, Any] = {
            "ServiceCode": service,
            "Filters": flt,
            "FormatVersion": "aws_v1",
            "MaxResults": 100,
        }
        if token:
            kw["NextToken"] = token
        page = client.get_products(**kw)
        out += [json.loads(p) if isinstance(p, str) else p for p in page.get("PriceList", [])]
        token = page.get("NextToken")
        if not token:
            return out


def _dimensions(item: dict) -> list[dict]:
    dims = []
    for term in item.get("terms", {}).get("OnDemand", {}).values():
        dims += list(term.get("priceDimensions", {}).values())
    return dims


def _first_paid(item: dict) -> tuple[float, str] | None:
    """Lowest-tier non-zero USD price in an item, with its unit."""
    dims = sorted(_dimensions(item), key=lambda d: float(d.get("beginRange", 0) or 0))
    for d in dims:
        usd = float(d["pricePerUnit"].get("USD", 0))
        if usd > 0:
            return usd, d.get("unit", "")
    return None


def _per_gb(item: dict | None) -> float | None:
    if not item:
        return None
    p = _first_paid(item)
    if p is None:
        return 0.0
    usd, unit = p
    return usd / 1000 if unit.upper() in ("TB", "TBYTES", "TERABYTES") else usd


def _pick(items: list[dict], suffix: str) -> dict | None:
    hits = [
        i for i in items if i.get("product", {}).get("attributes", {}).get("usagetype", "").endswith(suffix)
    ]
    return hits[0] if hits else None


def get_prices(pricing: Any, region: str) -> dict:
    """Return the rate table for ``region``. Raises ``ValueError`` for unknown Regions."""
    if region not in LOCATIONS:
        raise ValueError(f"no Price List location known for Region {region!r}; set rates manually")
    loc = LOCATIONS[region]
    rates: dict[str, Any] = {"region": region, "currency": "USD", "source": "AWS Price List API"}
    nat = _products(pricing, "AmazonEC2", {"productFamily": "NAT Gateway", "location": loc})
    rates["nat_processing_per_gb"] = _per_gb(_pick(nat, "NatGateway-Bytes"))
    vpc = _products(pricing, "AmazonVPC", {"location": loc})
    rates["interface_endpoint_per_gb"] = _per_gb(_pick(vpc, "VpcEndpoint-Bytes"))
    rates["gateway_endpoint_per_gb"] = 0.0
    rates["transit_gateway_per_gb"] = _per_gb(_pick(vpc, "TransitGateway-Bytes"))
    dt = _products(pricing, "AWSDataTransfer", {"fromLocation": loc})
    intra = [i for i in dt if i["product"]["attributes"].get("transferType") == "IntraRegion"]
    rates["inter_az_per_gb"] = _per_gb(intra[0]) if intra else None
    inter = [
        _per_gb(i) for i in dt if i["product"]["attributes"].get("transferType") == "InterRegion Outbound"
    ]
    inter = [x for x in inter if x]  # drop free and missing destinations
    rates["inter_region_per_gb"] = min(inter) if inter else None
    rates["inter_region_range"] = [min(inter), max(inter)] if inter else None
    out = [i for i in dt if i["product"]["attributes"].get("transferType") == "AWS Outbound"]
    rates["internet_out_per_gb"] = _per_gb(out[0]) if out else None
    ath = _products(pricing, "AmazonAthena", {"location": loc})
    scanned = _pick(ath, "DataScannedInTB") or _pick(ath, "DataScannedInBytes")
    rates["athena_per_tb"] = None if scanned is None else (_per_gb(scanned) or 0.0) * 1000
    missing = sorted(k for k, v in rates.items() if v is None)
    if missing:
        rates["unavailable_rates"] = missing
    return rates
