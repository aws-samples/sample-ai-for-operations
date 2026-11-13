# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
from unittest.mock import patch

import cache
from tools.resolve_amis import resolve_amis_impl


def setup_function():
    cache.clear()


@patch("tools.resolve_amis._live_images")
def test_live_images_found(mock_live):
    mock_live.return_value = [
        {"id": "ami-0abc", "name": "ubuntu-noble-24.04-amd64-server-20260101"},
        {"id": "ami-0def", "name": "ubuntu-noble-24.04-amd64-server-20251201"},
    ]
    r = resolve_amis_impl("us-east-1")
    assert r["ami_available"] is True
    assert r["source"] == "ec2-live"
    assert r["amis"][0]["id"] == "ami-0abc"


@patch("tools.resolve_amis._live_images", return_value=[])
def test_no_ami_is_a_fact_not_error(mock_live):
    # The eu-south-2 opt-in region case: no AMI published.
    r = resolve_amis_impl("eu-south-2")
    assert r["ami_available"] is False
    assert r["amis"] == []
    assert "error" not in r


@patch("tools.resolve_amis._live_images", return_value=None)
def test_live_unreachable_reports_unavailable(mock_live):
    # try_live returned None (unreachable / denied) -> treated as no AMI.
    r = resolve_amis_impl("me-south-1")
    assert r["ami_available"] is False


@patch("tools.resolve_amis._ssm_public_ami")
def test_ssm_public_param_preferred(mock_ssm):
    mock_ssm.return_value = {"id": "ami-0ssm", "name": "/aws/service/canonical/..."}
    r = resolve_amis_impl("us-east-1", ssm_param="/aws/service/canonical/ubuntu/...")
    assert r["source"] == "ssm-public-parameter"
    assert r["amis"][0]["id"] == "ami-0ssm"
