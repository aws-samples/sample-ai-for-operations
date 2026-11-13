# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
import json
from unittest.mock import MagicMock, patch

import cache
from tools.resolve_instance_offerings import resolve_instance_offerings_impl


def setup_function():
    cache.clear()


def _pricing_page(types):
    return [
        {
            "PriceList": [
                json.dumps({"product": {"attributes": {"instanceType": t}}})
                for t in types
            ]
        }
    ]


@patch("tools.resolve_instance_offerings._live_offered", return_value=None)
@patch("tools.resolve_instance_offerings.pricing_client")
def test_pricing_specific_type_offered(mock_pricing, mock_live):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = _pricing_page(["m6i.large"])
    client.get_paginator.return_value = paginator
    mock_pricing.return_value = client

    r = resolve_instance_offerings_impl("eu-south-2", instance_type="m6i.large")
    assert r["offerings"][0]["offered"] is True
    assert r["offerings"][0]["source"] == "pricing-api"
    assert r["offerings"][0]["confidence"] == "medium"


@patch("tools.resolve_instance_offerings._live_offered", return_value=None)
@patch("tools.resolve_instance_offerings.pricing_client")
def test_pricing_specific_type_not_offered(mock_pricing, mock_live):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = _pricing_page([])  # nothing offered
    client.get_paginator.return_value = paginator
    mock_pricing.return_value = client

    r = resolve_instance_offerings_impl("eu-south-2", instance_type="p5.48xlarge")
    assert r["offerings"][0]["offered"] is False


@patch("tools.resolve_instance_offerings._live_offered")
def test_live_offerings_when_enabled(mock_live):
    mock_live.return_value = {"m6i.large", "c6i.large"}
    r = resolve_instance_offerings_impl("us-east-1")
    assert {o["instance_type"] for o in r["offerings"]} == {"m6i.large", "c6i.large"}
    assert all(o["source"] == "ec2-live" for o in r["offerings"])
