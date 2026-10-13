# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Hypothesis property tests for src.intake.merge_event_message.merge_event_message.

Properties tested:
  - Idempotence: merge(merge(e, m), m) == merge(e, m)
  - Order independence (accounts): merging the same set of account messages in
    any order produces the same set of affectedAccounts.
"""

from __future__ import annotations

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from src.intake.merge_event_message import merge_event_message


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

account_id = st.from_regex(r"[0-9]{12}", fullmatch=True)

entity_strategy = st.fixed_dictionaries({
    "entityValue": st.from_regex(r"arn:aws:[a-z0-9]+:us-east-1:[0-9]{12}:[a-z]+/[a-zA-Z0-9-]+", fullmatch=True),
    "entityStatus": st.sampled_from(["IMPAIRED", "UNIMPAIRED", "UNKNOWN"]),
    "lastUpdatedTime": st.from_regex(r"2026-01-01T0[0-9]:00:00Z", fullmatch=True),
    "tags": st.fixed_dictionaries({}),
})

message_strategy = st.fixed_dictionaries({
    "eventArn": st.just("arn:aws:health:us-east-1::event/EC2/TEST/PROP-001"),
    "service": st.just("EC2"),
    "eventTypeCode": st.just("AWS_EC2_TEST"),
    "eventTypeCategory": st.sampled_from(["issue", "scheduledChange", "accountNotification"]),
    "eventScopeCode": st.sampled_from(["PUBLIC", "ACCOUNT_SPECIFIC"]),
    "statusCode": st.sampled_from(["open", "upcoming", "closed"]),
    "region": st.just("us-east-1"),
    "startTime": st.just("2026-01-01T00:00:00Z"),
    "lastUpdatedTime": st.sampled_from([
        "2026-01-01T01:00:00Z",
        "2026-01-01T02:00:00Z",
        "2026-01-01T03:00:00Z",
    ]),
    "endTime": st.just(""),
    "communicationId": st.just(""),
    "page": st.integers(min_value=1, max_value=3),
    "totalPages": st.just(3),
    "affectedAccounts": st.lists(account_id, min_size=1, max_size=5, unique=True),
    "affectedEntities": st.lists(entity_strategy, min_size=0, max_size=3),
    "eventDescription": st.just("Test event description."),
    "actionability": st.just("ACTIONABLE"),
    "personas": st.just([]),
    "raw": st.just({}),
})


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

@given(message=message_strategy)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_idempotence(message: dict) -> None:
    """merge(merge(None, m), m) == merge(None, m)

    Merging the same message twice must produce the same result as merging once.
    """
    first = merge_event_message(None, message)
    second = merge_event_message(first, message)

    # Accounts must be the same set
    assert set(second["affectedAccounts"]) == set(first["affectedAccounts"])
    # Entities must be the same set of entityValues
    assert set(second["affectedEntities"].keys()) == set(first["affectedEntities"].keys())
    # Pages received must include the same page
    assert message["page"] in second["pagesReceived"]


@given(
    message_a=message_strategy,
    message_b=message_strategy.map(
        lambda m: {**m, "affectedAccounts": [f"2222222{i:05d}" for i in range(1, 4)]}
    ),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_order_independence_accounts(message_a: dict, message_b: dict) -> None:
    """merge(merge(None, m_a), m_b).accounts == merge(merge(None, m_b), m_a).accounts

    Merging two messages for the same event in either order must result in
    the same set of affectedAccounts.
    """
    result_ab = merge_event_message(merge_event_message(None, message_a), message_b)
    result_ba = merge_event_message(merge_event_message(None, message_b), message_a)

    assert set(result_ab["affectedAccounts"]) == set(result_ba["affectedAccounts"])


@given(message=message_strategy)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_accounts_monotonically_grow(message: dict) -> None:
    """Merging a message never removes existing accounts."""
    first = merge_event_message(None, message)
    extra_acct = "999999999999"
    # Build a second message with the same event but a new account
    second_message = {**message, "affectedAccounts": [extra_acct]}
    second = merge_event_message(first, second_message)
    assert set(first["affectedAccounts"]).issubset(set(second["affectedAccounts"]))
    assert extra_acct in second["affectedAccounts"]


@given(message=message_strategy)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_event_arn_never_changes(message: dict) -> None:
    """eventArn is immutable once set."""
    first = merge_event_message(None, message)
    second = merge_event_message(first, message)
    assert second["eventArn"] == first["eventArn"] == message["eventArn"]
