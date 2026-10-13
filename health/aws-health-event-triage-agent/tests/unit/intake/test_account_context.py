# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Unit tests for the get_account_context tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.intake.account_context import (
    get_account_context,
    _build_ou_path,
    _determine_environment_type,
)

# Access the raw callable behind the @tool decorator
_get_account_context = get_account_context._tool_func


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_org_client(
    account_name: str = "my-account",
    parents_chain: list[dict] | None = None,
    tags: list[dict] | None = None,
):
    """Return a mock Organizations client with canned responses."""
    client = MagicMock()

    client.describe_account.return_value = {
        "Account": {"Name": account_name, "Id": "123456789012"},
    }

    # Default: account sits directly under root
    if parents_chain is None:
        parents_chain = [
            {"Parents": [{"Id": "r-root1", "Type": "ROOT"}]},
        ]

    client.list_parents.side_effect = list(parents_chain)

    if tags is None:
        tags = []
    client.list_tags_for_resource.return_value = {"Tags": tags}

    return client


# ---------------------------------------------------------------------------
# Successful retrieval
# ---------------------------------------------------------------------------

class TestSuccessfulRetrieval:
    @patch("src.intake.account_context.boto3")
    def test_returns_all_required_keys(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client()

        result = _get_account_context("123456789012")

        assert "account_id" in result
        assert "account_name" in result
        assert "ou_path" in result
        assert "tags" in result
        assert "environment_type" in result

    @patch("src.intake.account_context.boto3")
    def test_account_name_from_describe_account(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client(account_name="prod-us-east")

        result = _get_account_context("123456789012")

        assert result["account_name"] == "prod-us-east"

    @patch("src.intake.account_context.boto3")
    def test_tags_returned_as_dict(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client(
            tags=[
                {"Key": "Environment", "Value": "Production"},
                {"Key": "Team", "Value": "Platform"},
            ],
        )

        result = _get_account_context("123456789012")

        assert result["tags"] == {"Environment": "Production", "Team": "Platform"}


# ---------------------------------------------------------------------------
# API failure fallback
# ---------------------------------------------------------------------------

class TestAPIFailureFallback:
    @patch("src.intake.account_context.boto3")
    def test_fallback_on_describe_account_failure(self, mock_boto3):
        client = MagicMock()
        client.describe_account.side_effect = Exception("AccessDenied")
        mock_boto3.client.return_value = client

        result = _get_account_context("999999999999")

        assert result["account_name"] == "999999999999"
        assert result["ou_path"] == "unknown"
        assert result["tags"] == {}
        assert result["environment_type"] == "unknown"


# ---------------------------------------------------------------------------
# Production / non-production detection
# ---------------------------------------------------------------------------

class TestEnvironmentDetection:
    @patch("src.intake.account_context.boto3")
    def test_production_from_tag(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client(
            tags=[{"Key": "Environment", "Value": "Production"}],
        )

        result = _get_account_context("123456789012")

        assert result["environment_type"] == "production"

    @patch("src.intake.account_context.boto3")
    def test_non_production_from_tag(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client(
            tags=[{"Key": "Environment", "Value": "Staging"}],
        )

        result = _get_account_context("123456789012")

        assert result["environment_type"] == "non-production"

    @patch("src.intake.account_context.boto3")
    def test_production_from_ou_path(self, mock_boto3):
        client = _mock_org_client(tags=[])
        # OU chain: account -> "Production" OU -> Root
        client.list_parents.side_effect = [
            {"Parents": [{"Id": "ou-prod", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "r-root1", "Type": "ROOT"}]},
        ]
        client.describe_organizational_unit.return_value = {
            "OrganizationalUnit": {"Name": "Production", "Id": "ou-prod"},
        }
        mock_boto3.client.return_value = client

        result = _get_account_context("123456789012")

        assert result["environment_type"] == "production"

    @patch("src.intake.account_context.boto3")
    def test_non_production_default(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client(tags=[])

        result = _get_account_context("123456789012")

        assert result["environment_type"] == "non-production"


# ---------------------------------------------------------------------------
# OU path construction
# ---------------------------------------------------------------------------

class TestOUPathConstruction:
    @patch("src.intake.account_context.boto3")
    def test_nested_ou_path(self, mock_boto3):
        client = _mock_org_client()
        client.list_parents.side_effect = [
            {"Parents": [{"Id": "ou-useast", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "ou-prod", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "r-root1", "Type": "ROOT"}]},
        ]
        client.describe_organizational_unit.side_effect = [
            {"OrganizationalUnit": {"Name": "US-East", "Id": "ou-useast"}},
            {"OrganizationalUnit": {"Name": "Production", "Id": "ou-prod"}},
        ]
        mock_boto3.client.return_value = client

        result = _get_account_context("123456789012")

        assert result["ou_path"] == "Root/Production/US-East"

    @patch("src.intake.account_context.boto3")
    def test_direct_root_path(self, mock_boto3):
        mock_boto3.client.return_value = _mock_org_client()

        result = _get_account_context("123456789012")

        assert result["ou_path"] == "Root"
