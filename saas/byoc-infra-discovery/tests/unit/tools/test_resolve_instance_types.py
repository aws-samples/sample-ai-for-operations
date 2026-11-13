# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
import json
from unittest.mock import MagicMock, patch

import cache
from tools.resolve_instance_types import resolve_instance_types_impl


def setup_function():
    cache.clear()


def _pricing_page(items):
    return [
        {
            "PriceList": [
                json.dumps({"product": {"attributes": attrs}}) for attrs in items
            ]
        }
    ]


@patch("tools.resolve_instance_types._live_enrich", return_value=None)
@patch("tools.resolve_instance_types.pricing_client")
def test_pricing_fallback_for_non_enabled(mock_pricing, mock_live):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = _pricing_page(
        [
            {"instanceType": "m6i.large", "vcpu": "2", "memory": "8 GiB",
             "physicalProcessor": "Intel Xeon", "storage": "EBS only"},
            {"instanceType": "m6i.large", "vcpu": "2", "memory": "8 GiB"},  # dup ignored
        ]
    )
    client.get_paginator.return_value = paginator
    mock_pricing.return_value = client

    r = resolve_instance_types_impl("eu-south-2")
    assert len(r["instance_types"]) == 1
    it = r["instance_types"][0]
    assert it["name"] == "m6i.large"
    assert it["vcpu"] == 2
    assert it["memory_mib"] == 8192
    assert it["source"] == "pricing-api"
    assert it["confidence"] == "medium"
    assert it["arch"] is None  # coarse from pricing


@patch("tools.resolve_instance_types._live_enrich")
def test_live_enrichment_when_enabled(mock_live):
    mock_live.return_value = [
        {"name": "m6i.large", "vcpu": 2, "memory_mib": 8192, "processor": "x86_64",
         "arch": "x86_64", "local_storage": None, "source": "ec2-live", "confidence": "high"}
    ]
    r = resolve_instance_types_impl("us-east-1")
    assert r["instance_types"][0]["source"] == "ec2-live"
    assert r["instance_types"][0]["arch"] == "x86_64"


@patch("tools.resolve_instance_types._live_enrich", return_value=None)
@patch("tools.resolve_instance_types.pricing_client")
def test_family_filter(mock_pricing, mock_live):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = _pricing_page(
        [
            {"instanceType": "m6i.large", "vcpu": "2", "memory": "8 GiB"},
            {"instanceType": "c6i.large", "vcpu": "2", "memory": "4 GiB"},
        ]
    )
    client.get_paginator.return_value = paginator
    mock_pricing.return_value = client

    r = resolve_instance_types_impl("us-east-1", family="m6i")
    assert {t["name"] for t in r["instance_types"]} == {"m6i.large"}
