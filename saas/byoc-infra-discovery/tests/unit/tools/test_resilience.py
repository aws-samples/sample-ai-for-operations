# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from tools._resilience import try_live


def test_success_returns_value():
    assert try_live(lambda: {"ok": 1}, dataset="d", region="r") == {"ok": 1}


def test_unreachable_endpoint_returns_none():
    def _call():
        raise EndpointConnectionError(endpoint_url="https://ec2.me-south-1.amazonaws.com")

    assert try_live(_call, dataset="azs", region="me-south-1") is None


def test_scp_access_denied_returns_none():
    def _call():
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "SCP deny"}},
            "DescribeAvailabilityZones",
        )

    assert try_live(_call, dataset="azs", region="some-region") is None


def test_opt_in_required_returns_none():
    def _call():
        raise ClientError(
            {"Error": {"Code": "OptInRequired", "Message": "opt in"}}, "DescribeImages"
        )

    assert try_live(_call, dataset="amis", region="eu-south-2") is None


def test_unexpected_client_error_reraises():
    def _call():
        raise ClientError(
            {"Error": {"Code": "ValidationException", "Message": "bad param"}},
            "DescribeImages",
        )

    with pytest.raises(ClientError):
        try_live(_call, dataset="amis", region="us-east-1")
