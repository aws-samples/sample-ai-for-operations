# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from unittest.mock import MagicMock, patch

import cache
from tools.resolve_service_availability import resolve_service_availability_impl


def setup_function():
    cache.clear()


def _mock_ssm_services(service_regions):
    """service_regions: dict service -> list of region codes."""
    client = MagicMock()

    def _paginate(Path):
        service = Path.split("/services/")[1].split("/")[0]
        return [
            {"Parameters": [{"Value": r} for r in service_regions.get(service, [])]}
        ]

    paginator = MagicMock()
    paginator.paginate.side_effect = _paginate
    client.get_paginator.return_value = paginator
    return client


@patch("tools.resolve_service_availability.ssm_global_client")
def test_both_available(mock_ssm):
    mock_ssm.return_value = _mock_ssm_services(
        {"ec2": ["eu-south-2"], "eks": ["eu-south-2"]}
    )
    r = resolve_service_availability_impl("eu-south-2")
    assert r["services"] == {"ec2": True, "eks": True}
    assert r["source"] == "ssm-global-infrastructure"


@patch("tools.resolve_service_availability.ssm_global_client")
def test_eks_unavailable(mock_ssm):
    mock_ssm.return_value = _mock_ssm_services(
        {"ec2": ["xx-new-1"], "eks": []}
    )
    r = resolve_service_availability_impl("xx-new-1")
    assert r["services"] == {"ec2": True, "eks": False}


@patch("tools.resolve_service_availability.ssm_global_client")
def test_custom_service_list(mock_ssm):
    mock_ssm.return_value = _mock_ssm_services({"ec2": ["us-east-1"]})
    r = resolve_service_availability_impl("us-east-1", services=["ec2"])
    assert r["services"] == {"ec2": True}
