# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Unit tests for the consolidation tool.

Requirements covered: 3.1, 3.2, 3.3, 3.4, 3.5
"""

from __future__ import annotations

import pytest

from src.intake.merge_event_message import merge_event_message_tool as consolidate_notifications

# Access the raw callable behind the @tool decorator
_consolidate = consolidate_notifications._tool_func


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _acct(account_id: str, env: str = "non-production", name: str | None = None) -> dict:
    """Build an enriched account context dict."""
    return {
        "account_id": account_id,
        "account_name": name or f"account-{account_id[:4]}",
        "environment_type": env,
        "affected_resources": [],
    }


def _notif(
    arn: str = "arn:aws:health:us-east-1::event/EKS/123",
    service: str = "EKS",
    event_type: str = "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
    description: str = "EKS version end-of-life",
    accounts: list[dict] | None = None,
    status: str = "open",
) -> dict:
    """Build a minimal notification dict with enriched account context."""
    return {
        "arn": arn,
        "service": service,
        "eventTypeCode": event_type,
        "eventTypeCategory": "accountNotification",
        "statusCode": status,
        "region": "us-east-1",
        "eventDescription": description,
        "affectedAccounts": accounts or [_acct("111111111111")],
    }


# ---------------------------------------------------------------------------
# Req 3.1 – Single event across multiple accounts grouped into one view
# ---------------------------------------------------------------------------

class TestSingleEventMultipleAccounts:
    """Notifications for the same event across accounts produce one view."""

    def test_same_event_type_and_service_grouped(self):
        notifications = [
            _notif(arn="arn:1", accounts=[_acct("111111111111")]),
            _notif(arn="arn:2", accounts=[_acct("222222222222")]),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 1
        account_ids = {a["account_id"] for a in views[0]["affected_accounts"]}
        assert account_ids == {"111111111111", "222222222222"}

    def test_same_arn_deduplicated(self):
        notifications = [
            _notif(arn="arn:same", accounts=[_acct("111111111111")]),
            _notif(arn="arn:same", accounts=[_acct("222222222222")]),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 1
        assert len(views[0]["event_arns"]) == 1

    def test_duplicate_account_not_repeated(self):
        notifications = [
            _notif(accounts=[_acct("111111111111")]),
            _notif(accounts=[_acct("111111111111")]),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 1
        assert len(views[0]["affected_accounts"]) == 1


# ---------------------------------------------------------------------------
# Req 3.1 – Multiple distinct events produce separate views
# ---------------------------------------------------------------------------

class TestMultipleDistinctEvents:
    """Notifications for different events produce separate views."""

    def test_different_service_produces_separate_views(self):
        notifications = [
            _notif(service="EKS", event_type="AWS_EKS_EVENT"),
            _notif(service="RDS", event_type="AWS_RDS_EVENT"),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 2
        services = {v["service"] for v in views}
        assert services == {"EKS", "RDS"}

    def test_different_event_type_same_service_produces_separate_views(self):
        notifications = [
            _notif(event_type="AWS_EKS_LIFECYCLE"),
            _notif(event_type="AWS_EKS_SECURITY"),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 2


# ---------------------------------------------------------------------------
# Req 3.3, 3.4 – Environment breakdown (prod / non-prod)
# ---------------------------------------------------------------------------

class TestEnvironmentBreakdown:
    """Consolidated views categorize accounts as prod or non-prod."""

    def test_all_non_production(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "non-production"),
                _acct("222222222222", "non-production"),
            ])]
        )

        breakdown = views[0]["environment_breakdown"]
        assert breakdown["production_count"] == 0
        assert breakdown["non_production_count"] == 2

    def test_production_accounts_detected(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "production"),
                _acct("222222222222", "non-production"),
            ])]
        )

        breakdown = views[0]["environment_breakdown"]
        assert breakdown["production_count"] == 1
        assert breakdown["non_production_count"] == 1

    def test_account_environment_type_field(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "production"),
                _acct("222222222222", "non-production"),
            ])]
        )

        env_map = {
            a["account_id"]: a["environment_type"]
            for a in views[0]["affected_accounts"]
        }
        assert env_map["111111111111"] == "production"
        assert env_map["222222222222"] == "non-production"

    def test_all_production(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "production"),
                _acct("222222222222", "production"),
            ])]
        )

        breakdown = views[0]["environment_breakdown"]
        assert breakdown["production_count"] == 2
        assert breakdown["non_production_count"] == 0

    def test_account_name_preserved(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "production", name="prod-us-east"),
            ])]
        )

        acct = views[0]["affected_accounts"][0]
        assert acct["account_name"] == "prod-us-east"

    def test_unknown_environment_counted_as_non_production(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "unknown"),
            ])]
        )

        breakdown = views[0]["environment_breakdown"]
        assert breakdown["production_count"] == 0
        assert breakdown["non_production_count"] == 1


# ---------------------------------------------------------------------------
# Req 3.5 – Update existing view with new related notification
# ---------------------------------------------------------------------------

class TestUpdateExistingView:
    """New related notifications update existing views, not create new ones."""

    def test_adding_related_notification_does_not_increase_views(self):
        first_batch = [_notif(accounts=[_acct("111111111111")])]
        second_batch = first_batch + [_notif(accounts=[_acct("222222222222")])]

        views_before = _consolidate(notifications=first_batch)
        views_after = _consolidate(notifications=second_batch)

        assert len(views_after) == len(views_before) == 1

    def test_new_account_merged_into_existing_view(self):
        notifications = [
            _notif(accounts=[_acct("111111111111")]),
            _notif(accounts=[_acct("222222222222")]),
        ]
        views = _consolidate(notifications=notifications)

        account_ids = {a["account_id"] for a in views[0]["affected_accounts"]}
        assert "222222222222" in account_ids

    def test_environment_breakdown_updated_after_merge(self):
        notifications = [
            _notif(accounts=[_acct("111111111111", "non-production")]),
            _notif(accounts=[_acct("222222222222", "production")]),
        ]
        views = _consolidate(notifications=notifications)

        breakdown = views[0]["environment_breakdown"]
        assert breakdown["production_count"] == 1
        assert breakdown["non_production_count"] == 1


# ---------------------------------------------------------------------------
# Req 3.2, 3.3 – Org-wide summary included in each view
# ---------------------------------------------------------------------------

class TestOrgWideSummary:
    """Each consolidated view includes an organization-wide impact summary."""

    def test_summary_present_and_non_empty(self):
        views = _consolidate(
            notifications=[_notif(accounts=[_acct("111111111111")])]
        )

        assert views[0]["org_impact_summary"]
        assert isinstance(views[0]["org_impact_summary"], str)

    def test_summary_references_service(self):
        views = _consolidate(
            notifications=[_notif(service="EKS", accounts=[_acct("111111111111")])]
        )

        assert "EKS" in views[0]["org_impact_summary"]

    def test_summary_reflects_account_count(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111"),
                _acct("222222222222"),
            ])]
        )

        assert "2 account(s)" in views[0]["org_impact_summary"]

    def test_summary_reflects_environment_counts(self):
        views = _consolidate(
            notifications=[_notif(accounts=[
                _acct("111111111111", "production"),
                _acct("222222222222", "non-production"),
            ])]
        )

        summary = views[0]["org_impact_summary"]
        assert "1 production" in summary
        assert "1 non-production" in summary

    def test_each_view_has_its_own_summary(self):
        notifications = [
            _notif(service="EKS", event_type="AWS_EKS_EVENT", accounts=[_acct("111111111111")]),
            _notif(service="RDS", event_type="AWS_RDS_EVENT", accounts=[_acct("222222222222")]),
        ]
        views = _consolidate(notifications=notifications)

        summaries = [v["org_impact_summary"] for v in views]
        assert len(summaries) == 2
        assert all(s for s in summaries)
        services_in_summaries = {v["service"] for v in views if v["service"] in v["org_impact_summary"]}
        assert services_in_summaries == {"EKS", "RDS"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Additional edge-case coverage."""

    def test_empty_input_returns_empty_list(self):
        views = _consolidate(notifications=[])
        assert views == []

    def test_notification_missing_arn_still_grouped_by_type_service(self):
        notifications = [
            _notif(arn="", accounts=[_acct("111111111111")]),
            _notif(arn="", accounts=[_acct("222222222222")]),
        ]
        views = _consolidate(notifications=notifications)

        assert len(views) == 1

    def test_longer_description_preferred(self):
        notifications = [
            _notif(description="short"),
            _notif(description="a much longer and more informative description"),
        ]
        views = _consolidate(notifications=notifications)

        assert views[0]["eventDescription"] == "a much longer and more informative description"

    def test_view_contains_all_required_keys(self):
        views = _consolidate(
            notifications=[_notif(accounts=[_acct("111111111111")])]
        )

        required_keys = {
            "event_key",
            "event_arns",
            "service",
            "eventTypeCode",
            "eventDescription",
            "affected_accounts",
            "environment_breakdown",
            "org_impact_summary",
        }
        assert required_keys.issubset(views[0].keys())

    def test_plain_string_account_id_fallback(self):
        """Plain string account IDs are accepted as a fallback."""
        views = _consolidate(
            notifications=[{
                "arn": "arn:test",
                "service": "EKS",
                "eventTypeCode": "AWS_EKS_EVENT",
                "eventDescription": "test",
                "affectedAccounts": ["111111111111"],
            }]
        )

        acct = views[0]["affected_accounts"][0]
        assert acct["account_id"] == "111111111111"
        assert acct["environment_type"] == "unknown"
