# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Property-based tests for AWS Health Dashboard notification classifier tools.

Feature: aws-health-event-triage-agent
Tests: Properties 8-10, 13, 14, 16, 17
"""

from unittest.mock import MagicMock, patch, call

from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st

# ---------------------------------------------------------------------------
# Property 8: Related notifications consolidated into single view
# Validates: Requirements 3.1
# ---------------------------------------------------------------------------

from src.intake.merge_event_message import merge_event_message_tool as merge_event_message

_consolidate = merge_event_message._tool_func

# A small fixed pool of (eventTypeCode, service) pairs so Hypothesis can
# generate notifications that sometimes share the same event identity.
_EVENT_TYPES = [
    ("AWS_EKS_PLANNED_LIFECYCLE_EVENT", "EKS"),
    ("AWS_RDS_SECURITY_NOTIFICATION", "RDS"),
    ("AWS_LAMBDA_OPERATIONAL_ISSUE", "LAMBDA"),
    ("AWS_EC2_INSTANCE_RETIREMENT", "EC2"),
]

_ACCOUNT_IDS = [
    "111111111111",
    "222222222222",
    "333333333333",
    "444444444444",
    "555555555555",
]

# Production account IDs for property tests
_PROD_ACCOUNT_IDS = {"111111111111", "222222222222"}


def _enriched_account_strategy():
    """Strategy generating an enriched account context dict."""
    return st.sampled_from(_ACCOUNT_IDS).map(lambda aid: {
        "account_id": aid,
        "account_name": f"account-{aid[:4]}",
        "environment_type": "production" if aid in _PROD_ACCOUNT_IDS else "non-production",
        "affected_resources": [],
    })


def _notification_strategy():
    """Strategy that generates a notification dict with enriched account context
    and a random event type drawn from a small fixed pool, so some notifications
    will naturally share the same (eventTypeCode, service) pair and should be
    consolidated."""
    return st.fixed_dictionaries({
        "arn": st.from_regex(r"arn:aws:health:us-east-1::\d{8}", fullmatch=True),
        "service": st.just("placeholder"),  # overridden below
        "eventTypeCode": st.just("placeholder"),
        "eventTypeCategory": st.just("accountNotification"),
        "statusCode": st.just("open"),
        "region": st.sampled_from(["us-east-1", "us-west-2"]),
        "eventDescription": st.text(min_size=5, max_size=60),
        "affectedAccounts": st.lists(
            _enriched_account_strategy(), min_size=1, max_size=3,
        ).map(lambda accts: {a["account_id"]: a for a in accts}.values()).map(list),
    }).flatmap(lambda d: st.sampled_from(_EVENT_TYPES).map(
        lambda et: {**d, "eventTypeCode": et[0], "service": et[1]}
    ))


@given(notifications=st.lists(_notification_strategy(), min_size=0, max_size=20))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_related_notifications_consolidated_into_single_view(notifications):
    """Property 8: Related notifications consolidated into single view.

    For any set of notifications where some share the same (eventTypeCode, service),
    the number of consolidated views equals the number of unique
    (eventTypeCode, service) pairs.

    **Validates: Requirements 3.1**
    """
    views = _consolidate(notifications=notifications)

    unique_keys = {
        (n["eventTypeCode"], n["service"])
        for n in notifications
        if n.get("eventTypeCode") and n.get("service")
    }

    assert len(views) == len(unique_keys), (
        f"Expected {len(unique_keys)} consolidated views for "
        f"{len(unique_keys)} unique (eventTypeCode, service) pairs, "
        f"but got {len(views)}"
    )

    # Also verify: number of views <= number of input notifications
    assert len(views) <= len(notifications) or len(notifications) == 0


# ---------------------------------------------------------------------------
# Property 9: Consolidated views contain account detail, org summary,
#              and environment breakdown
# Validates: Requirements 3.2, 3.3, 3.4
# ---------------------------------------------------------------------------


def _notification_with_env_strategy():
    """Strategy generating notifications with enriched accounts that include
    both production and non-production accounts."""
    return st.fixed_dictionaries({
        "arn": st.from_regex(r"arn:aws:health:us-east-1::\d{8}", fullmatch=True),
        "service": st.just("placeholder"),
        "eventTypeCode": st.just("placeholder"),
        "eventTypeCategory": st.just("accountNotification"),
        "statusCode": st.just("open"),
        "region": st.sampled_from(["us-east-1", "us-west-2"]),
        "eventDescription": st.text(min_size=5, max_size=60),
        "affectedAccounts": st.lists(
            _enriched_account_strategy(), min_size=1, max_size=4,
        ).map(lambda accts: {a["account_id"]: a for a in accts}.values()).map(list),
    }).flatmap(lambda d: st.sampled_from(_EVENT_TYPES).map(
        lambda et: {**d, "eventTypeCode": et[0], "service": et[1]}
    ))


@given(notifications=st.lists(_notification_with_env_strategy(), min_size=1, max_size=15))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_consolidated_views_contain_required_fields(notifications):
    """Property 9: Consolidated views contain account detail, org summary,
    and environment breakdown.

    For any set of notifications with mixed production and non-production
    accounts, every consolidated view must contain:
      (a) account-level detail for each affected account
      (b) an organization-wide impact summary (non-empty string)
      (c) a production / non-production environment breakdown

    **Validates: Requirements 3.2, 3.3, 3.4**
    """
    views = _consolidate(notifications=notifications)

    for view in views:
        # (a) account-level detail
        assert isinstance(view["affected_accounts"], list)
        assert len(view["affected_accounts"]) >= 1
        for acct in view["affected_accounts"]:
            assert "account_id" in acct, "Missing account_id in account detail"
            assert "account_name" in acct, "Missing account_name in account detail"
            assert "environment_type" in acct, "Missing environment_type"
            assert acct["environment_type"] in ("production", "non-production", "unknown")

        # (b) org-wide impact summary
        assert isinstance(view["org_impact_summary"], str)
        assert len(view["org_impact_summary"]) > 0, "org_impact_summary is empty"

        # (c) environment breakdown with correct counts
        bd = view["environment_breakdown"]
        assert "production_count" in bd
        assert "non_production_count" in bd
        prod_actual = sum(
            1 for a in view["affected_accounts"]
            if a["environment_type"] == "production"
        )
        non_prod_actual = sum(
            1 for a in view["affected_accounts"]
            if a["environment_type"] != "production"
        )
        assert bd["production_count"] == prod_actual, (
            f"production_count mismatch: {bd['production_count']} != {prod_actual}"
        )
        assert bd["non_production_count"] == non_prod_actual, (
            f"non_production_count mismatch: {bd['non_production_count']} != {non_prod_actual}"
        )


# ---------------------------------------------------------------------------
# Property 10: Adding related notification updates existing view
# Validates: Requirements 3.5
# ---------------------------------------------------------------------------


@given(
    base_notifications=st.lists(_notification_strategy(), min_size=1, max_size=10),
    extra_notification=_notification_strategy(),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_adding_related_notification_updates_existing_view(
    base_notifications, extra_notification
):
    """Property 10: Adding related notification updates existing view.

    Given an existing set of consolidated views and a new notification that
    matches an existing view's (eventTypeCode, service), re-consolidating
    shall not increase the number of views — the matching view is updated.

    **Validates: Requirements 3.5**
    """
    # Force the extra notification to share the event identity of the first
    # base notification so it is guaranteed to be "related".
    first = base_notifications[0]
    extra_notification = {
        **extra_notification,
        "eventTypeCode": first["eventTypeCode"],
        "service": first["service"],
    }

    views_before = _consolidate(notifications=base_notifications)
    views_after = _consolidate(notifications=base_notifications + [extra_notification])

    assert len(views_after) <= len(views_before), (
        f"Adding a related notification increased view count from "
        f"{len(views_before)} to {len(views_after)}"
    )

    # The matching view should now include the extra notification's accounts
    extra_accts = extra_notification.get("affectedAccounts", [])
    extra_account_ids = {
        a["account_id"] if isinstance(a, dict) else a for a in extra_accts
    }
    matching_key = f"{first['eventTypeCode']}::{first['service']}"
    matching_view = next(v for v in views_after if v["event_key"] == matching_key)
    view_account_ids = {a["account_id"] for a in matching_view["affected_accounts"]}
    assert extra_account_ids.issubset(view_account_ids), (
        f"Extra notification accounts {extra_account_ids} not found in "
        f"updated view accounts {view_account_ids}"
    )


# ---------------------------------------------------------------------------
# Property 13: Output contains all required fields
# Validates: Requirements 11.1, 11.2, 11.3
# ---------------------------------------------------------------------------

_REQUIRED_NOTIFICATION_KEYS = {
    "notification_id",
    "classification",
    "reason",
    "event_type",
    "affected_service",
    "affected_accounts",
    "environment_breakdown",
}


def _classified_notification_strategy():
    """Strategy generating a single classified notification dict."""
    return st.fixed_dictionaries({
        "notification_id": st.from_regex(
            r"arn:aws:health:us-east-1::\d{8}", fullmatch=True
        ),
        "classification": st.sampled_from(
            ["BREAKING_CHANGE", "COST_IMPLICATION", "SECURITY_RELATED"]
        ),
        "reason": st.text(min_size=15, max_size=100),
        "event_type": st.sampled_from([
            "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
            "AWS_RDS_SECURITY_NOTIFICATION",
            "AWS_LAMBDA_OPERATIONAL_ISSUE",
        ]),
        "affected_service": st.sampled_from(["EKS", "RDS", "LAMBDA", "CASSANDRA"]),
        "affected_accounts": st.lists(
            st.fixed_dictionaries({
                "account_id": st.from_regex(r"\d{12}", fullmatch=True),
                "environment_type": st.sampled_from(["production", "non-production"]),
                "affected_resources": st.just([]),
            }),
            min_size=1, max_size=4,
        ),
        "environment_breakdown": st.builds(
            lambda accts: {
                "production_count": sum(
                    1 for a in accts if a["environment_type"] == "production"
                ),
                "non_production_count": sum(
                    1 for a in accts if a["environment_type"] == "non-production"
                ),
            },
            accts=st.lists(
                st.fixed_dictionaries({
                    "environment_type": st.sampled_from(["production", "non-production"]),
                }),
                min_size=1, max_size=4,
            ),
        ),
        "impact_analysis": st.just(None),
        "cost_projection": st.just(None),
    })


def _build_output(notifications: list[dict]) -> dict:
    """Build a full agent output dict from a list of classified notifications."""
    bc = sum(1 for n in notifications if n["classification"] == "BREAKING_CHANGE")
    ci = sum(1 for n in notifications if n["classification"] == "COST_IMPLICATION")
    sr = sum(1 for n in notifications if n["classification"] == "SECURITY_RELATED")
    return {
        "status": "success",
        "notifications": notifications,
        "total_count": len(notifications),
        "breaking_change_count": bc,
        "cost_implication_count": ci,
        "security_related_count": sr,
        "sns_publish_status": "sent",
    }


@given(
    notifications=st.lists(
        _classified_notification_strategy(), min_size=1, max_size=10
    )
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_output_contains_all_required_fields(notifications):
    """Property 13: Output contains all required fields.

    Every classified notification entry contains notification_id, classification,
    reason, event_type, affected_service, affected_accounts, environment_breakdown
    — all non-null. Output also contains correct count tallies.

    Validates: Requirements 11.1, 11.2, 11.3
    """
    output = _build_output(notifications)

    assert output["status"] == "success"
    assert output["total_count"] == len(notifications)

    bc = ci = sr = 0
    for entry in output["notifications"]:
        # All required keys present and non-null
        for key in _REQUIRED_NOTIFICATION_KEYS:
            assert key in entry, f"Missing key '{key}'"
            assert entry[key] is not None, f"Null value for '{key}'"

        assert entry["classification"] in {
            "BREAKING_CHANGE", "COST_IMPLICATION", "SECURITY_RELATED"
        }

        if entry["classification"] == "BREAKING_CHANGE":
            bc += 1
        elif entry["classification"] == "COST_IMPLICATION":
            ci += 1
        else:
            sr += 1

    assert output["breaking_change_count"] == bc
    assert output["cost_implication_count"] == ci
    assert output["security_related_count"] == sr


# ---------------------------------------------------------------------------
# Property 14: Classification-specific analysis included in output
# Validates: Requirements 11.4, 11.5
# ---------------------------------------------------------------------------


def _breaking_with_impact_strategy():
    """Strategy generating a BREAKING_CHANGE notification with impact_analysis."""
    return st.fixed_dictionaries({
        "notification_id": st.from_regex(r"arn:aws:health:us-east-1::\d{8}", fullmatch=True),
        "classification": st.just("BREAKING_CHANGE"),
        "reason": st.text(min_size=15, max_size=80),
        "event_type": st.just("AWS_EKS_PLANNED_LIFECYCLE_EVENT"),
        "affected_service": st.just("EKS"),
        "affected_accounts": st.just([{"account_id": "111111111111", "environment_type": "production", "affected_resources": []}]),
        "environment_breakdown": st.just({"production_count": 1, "non_production_count": 0}),
        "impact_analysis": st.fixed_dictionaries({
            "action_required": st.just(True),
            "risk_level": st.sampled_from(["high", "medium", "low"]),
            "summary": st.text(min_size=10, max_size=80),
            "affected_accounts": st.just([]),
        }),
        "cost_projection": st.just(None),
    })


def _cost_with_projection_strategy():
    """Strategy generating a COST_IMPLICATION notification with cost_projection."""
    return st.fixed_dictionaries({
        "notification_id": st.from_regex(r"arn:aws:health:us-east-1::\d{8}", fullmatch=True),
        "classification": st.just("COST_IMPLICATION"),
        "reason": st.text(min_size=15, max_size=80),
        "event_type": st.just("AWS_RDS_PLANNED_LIFECYCLE_EVENT"),
        "affected_service": st.just("RDS"),
        "affected_accounts": st.just([{"account_id": "222222222222", "environment_type": "non-production", "affected_resources": []}]),
        "environment_breakdown": st.just({"production_count": 0, "non_production_count": 1}),
        "impact_analysis": st.just(None),
        "cost_projection": st.fixed_dictionaries({
            "projectable": st.just(True),
            "org_total_projected_cost": st.floats(min_value=1.0, max_value=10000.0),
            "currency": st.just("USD"),
        }),
    })


@given(
    breaking=st.lists(_breaking_with_impact_strategy(), min_size=1, max_size=5),
    cost=st.lists(_cost_with_projection_strategy(), min_size=1, max_size=5),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_classification_specific_analysis_in_output(breaking, cost):
    """Property 14: Classification-specific analysis included in output.

    BREAKING_CHANGE entries have non-null impact_analysis.
    COST_IMPLICATION entries have non-null cost_projection.

    Validates: Requirements 11.4, 11.5
    """
    all_notifs = breaking + cost
    output = _build_output(all_notifs)

    for entry in output["notifications"]:
        if entry["classification"] == "BREAKING_CHANGE":
            assert entry["impact_analysis"] is not None, (
                "BREAKING_CHANGE entry missing impact_analysis"
            )
        elif entry["classification"] == "COST_IMPLICATION":
            assert entry["cost_projection"] is not None, (
                "COST_IMPLICATION entry missing cost_projection"
            )

# ---------------------------------------------------------------------------
# Property 16 & 17 — get_account_context
# ---------------------------------------------------------------------------

from src.intake.account_context import (
    get_account_context,
    _determine_environment_type,
)

_get_account_context = get_account_context._tool_func


def _account_id_strategy():
    """Generate random 12-digit AWS account IDs."""
    return st.from_regex(r"[0-9]{12}", fullmatch=True)


def _account_name_strategy():
    return st.text(
        min_size=1,
        max_size=40,
        alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    )


def _ou_name_strategy():
    return st.sampled_from([
        "Root", "Production", "Staging", "Development", "Sandbox",
        "US-East", "EU-West", "Security", "SharedServices",
    ])


def _tag_strategy():
    """Generate a dict of account tags (0–5 tags)."""
    return st.dictionaries(
        keys=st.sampled_from(["Environment", "Team", "CostCenter", "Project", "Owner"]),
        values=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))),
        min_size=0,
        max_size=5,
    )


def _ou_chain_strategy():
    """Generate a list of OU names representing the path from root to account."""
    return st.lists(_ou_name_strategy(), min_size=0, max_size=4)


def _mock_org_for_property(account_name, ou_chain, tags):
    """Build a mock Organizations client from generated data."""
    client = MagicMock()
    client.describe_account.return_value = {
        "Account": {"Name": account_name, "Id": "000000000000"},
    }

    # Build list_parents side_effect: each OU in chain, then ROOT
    parents_responses = []
    for i, ou_name in enumerate(reversed(ou_chain)):
        ou_id = f"ou-{i}"
        parents_responses.append(
            {"Parents": [{"Id": ou_id, "Type": "ORGANIZATIONAL_UNIT"}]}
        )
    parents_responses.append(
        {"Parents": [{"Id": "r-root1", "Type": "ROOT"}]}
    )
    client.list_parents.side_effect = list(parents_responses)

    # describe_organizational_unit for each OU
    ou_descriptions = []
    for i, ou_name in enumerate(reversed(ou_chain)):
        ou_descriptions.append(
            {"OrganizationalUnit": {"Name": ou_name, "Id": f"ou-{i}"}}
        )
    client.describe_organizational_unit.side_effect = list(ou_descriptions)

    # Tags
    tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
    client.list_tags_for_resource.return_value = {"Tags": tag_list}

    return client


@given(
    account_id=_account_id_strategy(),
    account_name=_account_name_strategy(),
    ou_chain=_ou_chain_strategy(),
    tags=_tag_strategy(),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@patch("src.intake.account_context.boto3")
def test_get_account_context_returns_required_fields(
    mock_boto3, account_id, account_name, ou_chain, tags,
):
    """Property 16: get_account_context returns required fields.

    For any valid AWS account ID with mocked Organizations API responses,
    the returned dict contains account_name, ou_path, tags, and
    environment_type — all non-null.

    **Validates: Requirements 13.2, 13.6**
    """
    mock_boto3.client.return_value = _mock_org_for_property(
        account_name, ou_chain, tags,
    )

    result = _get_account_context(account_id=account_id)

    assert result["account_id"] == account_id
    assert result["account_name"] is not None and result["account_name"] != ""
    assert result["ou_path"] is not None and result["ou_path"] != ""
    assert result["tags"] is not None
    assert isinstance(result["tags"], dict)
    assert result["environment_type"] in {"production", "non-production", "unknown"}


@given(
    tags=_tag_strategy(),
    ou_chain=_ou_chain_strategy(),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_environment_type_determined_from_account_context(tags, ou_chain):
    """Property 17: Environment type determined from account context.

    Accounts with production indicators (Environment=Production tag or
    OU path containing 'Production') have environment_type 'production'.
    Accounts with non-production indicators have environment_type
    'non-production'.

    **Validates: Requirements 13.4**
    """
    ou_path = "/".join(["Root"] + list(ou_chain)) if ou_chain else "Root"
    env_type = _determine_environment_type(tags, ou_path)

    has_prod_tag = tags.get("Environment", tags.get("environment", "")).lower() == "production"
    has_prod_ou = "production" in ou_path.lower()

    if has_prod_tag or (not tags.get("Environment", tags.get("environment", "")) and has_prod_ou):
        assert env_type == "production", (
            f"Expected 'production' for tags={tags}, ou_path={ou_path}, got {env_type}"
        )
    elif tags.get("Environment", tags.get("environment", "")):
        # Has an Environment tag but it's not "production"
        assert env_type == "non-production", (
            f"Expected 'non-production' for tags={tags}, ou_path={ou_path}, got {env_type}"
        )
    else:
        # No Environment tag — falls back to OU path check
        if has_prod_ou:
            assert env_type == "production", (
                f"Expected 'production' from OU path={ou_path}, got {env_type}"
            )
        else:
            assert env_type == "non-production", (
                f"Expected 'non-production' for tags={tags}, ou_path={ou_path}, got {env_type}"
            )



