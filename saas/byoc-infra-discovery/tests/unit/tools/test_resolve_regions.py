# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from unittest.mock import MagicMock, patch

import cache
from tools.resolve_regions import resolve_regions_impl


def _mock_ssm_with_regions(region_codes, long_names):
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Parameters": [
                {"Name": f"/aws/service/global-infrastructure/regions/{c}"}
                for c in region_codes
            ]
        }
    ]
    client.get_paginator.return_value = paginator
    client.get_parameter.side_effect = lambda Name: {
        "Parameter": {"Value": long_names[Name.rsplit("/", 2)[-2]]}
    }
    return client


def setup_function():
    cache.clear()


@patch("tools.resolve_regions.ssm_global_client")
def test_single_region(mock_client):
    client = MagicMock()
    client.get_parameter.return_value = {"Parameter": {"Value": "Europe (Spain)"}}
    mock_client.return_value = client

    r = resolve_regions_impl("eu-south-2")
    assert r["regions"][0]["code"] == "eu-south-2"
    assert r["regions"][0]["long_name"] == "Europe (Spain)"
    assert r["regions"][0]["source"] == "ssm-global-infrastructure"
    assert r["regions"][0]["confidence"] == "high"


@patch("tools.resolve_regions.ssm_global_client")
def test_all_regions(mock_client):
    mock_client.return_value = _mock_ssm_with_regions(
        ["us-east-1", "eu-south-2"],
        {"us-east-1": "US East (N. Virginia)", "eu-south-2": "Europe (Spain)"},
    )
    r = resolve_regions_impl()
    codes = {x["code"] for x in r["regions"]}
    assert codes == {"us-east-1", "eu-south-2"}


@patch("tools.resolve_regions.ssm_global_client")
def test_long_name_missing(mock_client):
    client = MagicMock()

    class ParamNotFound(Exception):
        pass

    client.exceptions.ParameterNotFound = ParamNotFound

    def _raise(Name):
        raise ParamNotFound()

    client.get_parameter.side_effect = _raise
    mock_client.return_value = client

    r = resolve_regions_impl("xx-new-1")
    assert r["regions"][0]["long_name"] is None
