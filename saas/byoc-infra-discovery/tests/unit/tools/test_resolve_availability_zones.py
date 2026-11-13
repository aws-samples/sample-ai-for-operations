# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from unittest.mock import MagicMock, patch

import cache
from tools.resolve_availability_zones import resolve_availability_zones_impl


def setup_function():
    cache.clear()


def _mock_ssm_azs(region, az_ids):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Parameters": [
                {
                    "Name": (
                        "/aws/service/global-infrastructure/regions/"
                        f"{region}/availability-zones/{az}"
                    )
                }
                for az in az_ids
            ]
        }
    ]
    client.get_paginator.return_value = paginator
    return client


@patch("tools.resolve_availability_zones._fetch_live_names", return_value=None)
@patch("tools.resolve_availability_zones.ssm_global_client")
def test_non_enabled_region_ids_only(mock_ssm, mock_live):
    mock_ssm.return_value = _mock_ssm_azs("ap-southeast-7", ["apse7-az1", "apse7-az2", "apse7-az3"])
    r = resolve_availability_zones_impl("ap-southeast-7")
    assert r["az_names_available"] is False
    assert r["source"] == "ssm-global-infrastructure"
    assert [a["az_id"] for a in r["azs"]] == ["apse7-az1", "apse7-az2", "apse7-az3"]
    # never fabricates names
    assert all("az_name" not in a for a in r["azs"])


@patch("tools.resolve_availability_zones._fetch_live_names")
@patch("tools.resolve_availability_zones.ssm_global_client")
def test_enabled_region_adds_names(mock_ssm, mock_live):
    mock_ssm.return_value = _mock_ssm_azs("us-east-1", ["use1-az1", "use1-az2"])
    mock_live.return_value = {"use1-az1": "us-east-1a", "use1-az2": "us-east-1b"}
    r = resolve_availability_zones_impl("us-east-1")
    assert r["az_names_available"] is True
    assert r["source"] == "ec2-live"
    names = {a["az_id"]: a["az_name"] for a in r["azs"]}
    assert names["use1-az1"] == "us-east-1a"


def test_invalid_region_raises():
    import pytest

    with pytest.raises(ValueError):
        resolve_availability_zones_impl("")
