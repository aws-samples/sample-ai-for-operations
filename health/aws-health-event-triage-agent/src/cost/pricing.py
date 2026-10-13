# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Workflow tool: get_pricing.

Retrieves unit pricing from the AWS Price List Query API, fronted by an
in-memory PricingCache (7-day TTL for Build; a production deployment would
back this with DynamoDB per design §3.4.1). Falls back to
config/pricing-overrides.json when the API call fails or no matching SKU
is found.

The AWS Price List Query API is only available in specific Regions
(us-east-1, eu-central-1, ap-south-1) regardless of the deployment Region.

Never raises — always returns a dict with 'source' indicating where the
price came from, or 'source': 'unavailable' with a reason.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import boto3

from src import config

logger = logging.getLogger(__name__)

# Price List API is only available in these Regions
PRICE_LIST_REGION = os.environ.get("PRICE_LIST_API_REGION", "us-east-1")

_DEFAULT_OVERRIDES_PATH = Path(__file__).parents[2] / "config" / "pricing-overrides.json"

_CACHE_TTL_SECONDS = int(os.environ.get("PRICING_CACHE_TTL_SECONDS", str(7 * 24 * 60 * 60)))

# In-memory pricing cache: {cache_key: (price_dict, expiry_epoch)}
_pricing_cache: dict[str, tuple[dict, float]] = {}

_overrides_cache: dict | None = None


def _load_overrides() -> dict:
    global _overrides_cache
    if _overrides_cache is not None:
        return _overrides_cache
    path = Path(os.environ.get("PRICING_OVERRIDES_PATH", str(_DEFAULT_OVERRIDES_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            _overrides_cache = json.load(f)
    except FileNotFoundError:
        _overrides_cache = {}
    except Exception as exc:
        logger.warning("Could not load pricing overrides from %s: %s", path, exc)
        _overrides_cache = {}
    return _overrides_cache


def _cache_key(service: str, dimension: str, region: str) -> str:
    return f"{service}::{dimension}::{region}"


def _cache_get(key: str) -> dict | None:
    entry = _pricing_cache.get(key)
    if entry is None:
        return None
    price, expiry = entry
    if time.time() > expiry:
        del _pricing_cache[key]
        return None
    return price


def _cache_put(key: str, price: dict) -> None:
    _pricing_cache[key] = (price, time.time() + _CACHE_TTL_SECONDS)


def _override_lookup(service: str, dimension: str) -> dict | None:
    overrides = _load_overrides()
    service_overrides = overrides.get(service, {})
    entry = service_overrides.get(dimension)
    if entry is None:
        return None
    return {
        "unitPrice": entry.get("unitPrice"),
        "unit": entry.get("unit", ""),
        "currency": entry.get("currency", "USD"),
        "source": "override",
        "retrievedAt": None,
    }


def _query_price_list_api(service: str, dimension: str, region: str, client=None) -> dict | None:
    """Query the AWS Price List Query API for a given service/dimension.

    Returns None if the API call fails or no matching price is found —
    the caller falls back to the config override.
    """
    try:
        pricing_client = client or boto3.client("pricing", region_name=PRICE_LIST_REGION)
        # Simplified filter set — Build-phase implementation. Exact SKU
        # attribute names are confirmed against the live API during
        # deployment testing (design §3.4.1 notes this explicitly).
        response = pricing_client.get_products(
            ServiceCode=service,
            Filters=[
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": dimension},
                {"Type": "TERM_MATCH", "Field": "regionCode", "Value": region},
            ],
            MaxResults=1,
        )
        price_list = response.get("PriceList", [])
        if not price_list:
            return None

        product = json.loads(price_list[0]) if isinstance(price_list[0], str) else price_list[0]
        terms = product.get("terms", {}).get("OnDemand", {})
        for term_key, term_value in terms.items():
            price_dims = term_value.get("priceDimensions", {})
            for dim_key, dim_value in price_dims.items():
                price_per_unit = dim_value.get("pricePerUnit", {})
                usd_price = price_per_unit.get("USD")
                if usd_price is not None:
                    return {
                        "unitPrice": float(usd_price),
                        "unit": dim_value.get("unit", ""),
                        "currency": "USD",
                        "source": "pricelist",
                        "retrievedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
        return None
    except Exception as exc:
        logger.warning("Price List API query failed for %s/%s/%s: %s", service, dimension, region, exc)
        return None


def get_pricing(service: str, dimension: str, region: str, client=None) -> dict:
    """Retrieve unit pricing for a service/dimension/region.

    Lookup order: PricingCache → Price List Query API → config override →
    unavailable.

    Args:
        service: AWS service code (e.g. "AmazonEKS", "AmazonRDS").
        dimension: Usage-type dimension string (e.g. "ClusterUsage",
            "vCPU-Hours:0002").
        region: AWS Region for the pricing lookup.
        client: Optional injected boto3 Pricing client (for tests).

    Returns:
        Dict with keys: unitPrice, unit, currency, source
        ("cache" | "pricelist" | "override" | "unavailable"), retrievedAt.
        When unavailable: unitPrice is None and a 'reason' key is present.
    """
    key = _cache_key(service, dimension, region)

    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "source": "cache"}

    api_result = _query_price_list_api(service, dimension, region, client=client)
    if api_result is not None:
        _cache_put(key, api_result)
        return api_result

    override_result = _override_lookup(service, dimension)
    if override_result is not None:
        return override_result

    return {
        "unitPrice": None,
        "unit": "",
        "currency": "USD",
        "source": "unavailable",
        "retrievedAt": None,
        "reason": f"No pricing data available for {service}/{dimension}/{region} "
                  f"from the Price List API or config overrides.",
    }
