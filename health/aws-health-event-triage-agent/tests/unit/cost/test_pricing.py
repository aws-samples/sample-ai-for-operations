# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.cost.pricing.get_pricing."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock

import pytest

import src.cost.pricing as pricing_mod
from src.cost.pricing import get_pricing


@pytest.fixture(autouse=True)
def _reset_caches():
    """Reset module-level caches between tests."""
    pricing_mod._pricing_cache.clear()
    pricing_mod._overrides_cache = None
    yield
    pricing_mod._pricing_cache.clear()
    pricing_mod._overrides_cache = None


def _make_price_list_response(unit_price: str, unit: str = "Hrs") -> dict:
    product = {
        "terms": {
            "OnDemand": {
                "term1": {
                    "priceDimensions": {
                        "dim1": {
                            "pricePerUnit": {"USD": unit_price},
                            "unit": unit,
                        }
                    }
                }
            }
        }
    }
    return {"PriceList": [json.dumps(product)]}


class TestPriceListApiSuccess:
    def test_returns_pricelist_source(self):
        client = MagicMock()
        client.get_products.return_value = _make_price_list_response("0.10")
        result = get_pricing("AmazonEKS", "ClusterUsage", "us-east-1", client=client)
        assert result["source"] == "pricelist"
        assert result["unitPrice"] == 0.10

    def test_caches_result(self):
        client = MagicMock()
        client.get_products.return_value = _make_price_list_response("0.10")
        get_pricing("AmazonEKS", "ClusterUsage", "us-east-1", client=client)

        # Second call should hit cache, not call the API again
        result2 = get_pricing("AmazonEKS", "ClusterUsage", "us-east-1", client=client)
        assert result2["source"] == "cache"
        assert client.get_products.call_count == 1


class TestPriceListApiFailureFallsBackToOverride:
    def test_api_exception_falls_back(self, tmp_path):
        overrides = {"AmazonEKS": {"ClusterUsage": {"unitPrice": 0.10, "unit": "hour", "currency": "USD"}}}
        path = tmp_path / "overrides.json"
        path.write_text(json.dumps(overrides))
        os.environ["PRICING_OVERRIDES_PATH"] = str(path)
        try:
            client = MagicMock()
            client.get_products.side_effect = Exception("API unavailable")
            result = get_pricing("AmazonEKS", "ClusterUsage", "us-east-1", client=client)
            assert result["source"] == "override"
            assert result["unitPrice"] == 0.10
        finally:
            del os.environ["PRICING_OVERRIDES_PATH"]

    def test_empty_price_list_falls_back(self, tmp_path):
        overrides = {"AmazonRDS": {"ExtendedSupportYear1-2": {"unitPrice": 0.10, "unit": "vCPU-Hour", "currency": "USD"}}}
        path = tmp_path / "overrides.json"
        path.write_text(json.dumps(overrides))
        os.environ["PRICING_OVERRIDES_PATH"] = str(path)
        try:
            client = MagicMock()
            client.get_products.return_value = {"PriceList": []}
            result = get_pricing("AmazonRDS", "ExtendedSupportYear1-2", "us-east-1", client=client)
            assert result["source"] == "override"
        finally:
            del os.environ["PRICING_OVERRIDES_PATH"]


class TestTotalFailureReturnsUnavailable:
    def test_no_api_no_override_returns_unavailable(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("{}")
        os.environ["PRICING_OVERRIDES_PATH"] = str(path)
        try:
            client = MagicMock()
            client.get_products.side_effect = Exception("unavailable")
            result = get_pricing("UnknownService", "UnknownDimension", "us-east-1", client=client)
            assert result["source"] == "unavailable"
            assert result["unitPrice"] is None
            assert "reason" in result
        finally:
            del os.environ["PRICING_OVERRIDES_PATH"]


class TestNeverRaises:
    def test_malformed_price_list_response_does_not_raise(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("{}")
        os.environ["PRICING_OVERRIDES_PATH"] = str(path)
        try:
            client = MagicMock()
            client.get_products.return_value = {"PriceList": ["not valid json {{{"]}
            result = get_pricing("AmazonEKS", "ClusterUsage", "us-east-1", client=client)
            assert result["source"] == "unavailable"
        finally:
            del os.environ["PRICING_OVERRIDES_PATH"]
