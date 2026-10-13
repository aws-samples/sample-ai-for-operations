# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Test fixtures for AWS Health EventBridge events.

All account IDs are placeholders (123456789012). No real data.
"""

from __future__ import annotations


def _base_event(overrides: dict | None = None) -> dict:
    """Build a minimal valid EventBridge health event envelope."""
    detail = {
        "eventArn": "arn:aws:health:us-east-1::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/TEST-123",
        "service": "EC2",
        "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
        "eventTypeCategory": "issue",
        "eventScopeCode": "PUBLIC",
        "statusCode": "open",
        "region": "us-east-1",
        "startTime": "2026-01-01T00:00:00Z",
        "lastUpdatedTime": "2026-01-01T01:00:00Z",
        "eventDescription": [
            {"language": "en_US", "latestDescription": "Investigating EC2 connectivity issues."}
        ],
    }
    if overrides:
        detail.update(overrides)
    return {"source": "aws.health", "detail-type": "AWS Health Event", "detail": detail}


def scheduled_change_event() -> dict:
    """Scheduled change event (accountNotification scope)."""
    return _base_event({
        "eventArn": "arn:aws:health:us-east-1::event/EKS/AWS_EKS_PLANNED_LIFECYCLE_EVENT/TEST-456",
        "service": "EKS",
        "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
        "eventTypeCategory": "scheduledChange",
        "eventScopeCode": "ACCOUNT_SPECIFIC",
        "statusCode": "upcoming",
        "affectedAccount": "123456789012",
        "affectedEntities": [
            {
                "entityValue": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                "entityArn": "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster",
                "entityStatus": "IMPAIRED",
                "lastUpdatedTime": "2026-01-01T00:30:00Z",
                "tags": {"Environment": "production"},
            }
        ],
        "actionability": "ACTIONABLE",
    })


def account_notification_event() -> dict:
    """Account-specific notification (cost implication)."""
    return _base_event({
        "eventArn": "arn:aws:health:us-east-1::event/RDS/AWS_RDS_EXTENDED_SUPPORT/TEST-789",
        "service": "RDS",
        "eventTypeCode": "AWS_RDS_EXTENDED_SUPPORT",
        "eventTypeCategory": "accountNotification",
        "eventScopeCode": "ACCOUNT_SPECIFIC",
        "statusCode": "open",
        "affectedAccount": "123456789012",
        "actionability": "ACTIONABLE",
        "personas": ["account_owner", "billing_contact"],
        "eventDescription": [
            {
                "language": "en_US",
                "latestDescription": "Your RDS instance is entering extended support.",
            }
        ],
    })


def multi_page_event(page: int = 1, total_pages: int = 3) -> dict:
    """Multi-page event (page N of totalPages)."""
    accounts = [f"11111111{i:04d}" for i in range(1, 13)]  # 12 accounts per page
    return _base_event({
        "eventArn": "arn:aws:health:us-east-1::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/MULTI",
        "page": page,
        "totalPages": total_pages,
        "communicationId": "comm-abc-123",
        "affectedAccounts": accounts,
    })


def org_view_message(
    account: str = "123456789012",
    last_updated_time: str = "2026-01-01T01:00:00Z",
    page: int = 1,
    total_pages: int = 1,
    event_arn: str = "arn:aws:health:us-east-1::event/EKS/AWS_EKS_PLANNED_LIFECYCLE_EVENT/MULTI-ACCT",
) -> dict:
    """One organizational-view message for a multi-account event.

    Mirrors what AWS Health's org-wide EventBridge feed actually delivers:
    one message per (affectedAccount, page), all sharing eventArn and
    lastUpdatedTime for a single AWS update. Two calls with the same
    event_arn/last_updated_time but different `account` simulate the A/B
    fan-out described in req §1b — this is the fixture the pre-existing
    test suite lacked (single-account sandbox never exercised it).
    """
    return _base_event({
        "eventArn": event_arn,
        "service": "EKS",
        "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
        "eventTypeCategory": "scheduledChange",
        "eventScopeCode": "ACCOUNT_SPECIFIC",
        "statusCode": "upcoming",
        "affectedAccount": account,
        "lastUpdatedTime": last_updated_time,
        "page": page,
        "totalPages": total_pages,
        "affectedEntities": [
            {
                "entityValue": f"arn:aws:eks:us-east-1:{account}:cluster/my-cluster",
                "entityArn": f"arn:aws:eks:us-east-1:{account}:cluster/my-cluster",
                "entityStatus": "IMPAIRED",
                "lastUpdatedTime": last_updated_time,
                "tags": {"Environment": "production"},
            }
        ],
        "actionability": "ACTIONABLE",
    })


def closed_event() -> dict:
    """Closed event."""
    return _base_event({
        "statusCode": "closed",
        "endTime": "2026-01-01T06:00:00Z",
    })


def event_with_unknown_fields() -> dict:
    """Event containing unknown/future fields that should be preserved in 'raw'."""
    evt = _base_event()
    evt["detail"]["futureField"] = "somevalue"
    evt["detail"]["nestedFuture"] = {"a": 1, "b": 2}
    return evt


def malformed_event_missing_arn() -> dict:
    """Malformed event: missing eventArn."""
    evt = _base_event()
    del evt["detail"]["eventArn"]
    return evt


def malformed_event_not_dict() -> str:
    """Completely malformed event (not a dict at all)."""
    return "not-a-dict"


def bare_detail_event() -> dict:
    """Event passed as just the detail object (no envelope)."""
    return _base_event()["detail"]
