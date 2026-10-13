# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.intake.event_parser.

Requirements covered: R1.3 (parse native schema), R2 (idempotency key),
  R1.7 (unknown fields preserved).
"""

from __future__ import annotations

import pytest

from src.intake.event_parser import (
    HealthEventParseError,
    idempotency_key,
    is_closed,
    parse_health_event,
)
from tests.unit.intake.fixtures.health_event_fixtures import (
    account_notification_event,
    bare_detail_event,
    closed_event,
    event_with_unknown_fields,
    malformed_event_missing_arn,
    malformed_event_not_dict,
    multi_page_event,
    org_view_message,
    scheduled_change_event,
)


class TestParseIssueEvent:
    """Basic issue event parsing."""

    def test_returns_required_keys(self):
        """All required output keys are present."""
        result = parse_health_event(scheduled_change_event())
        expected_keys = {
            "eventArn", "service", "eventTypeCode", "eventTypeCategory",
            "eventScopeCode", "statusCode", "region", "startTime", "endTime",
            "lastUpdatedTime", "communicationId", "page", "totalPages",
            "affectedAccounts", "affectedEntities", "eventDescription",
            "actionability", "personas", "raw",
        }
        assert expected_keys.issubset(result.keys())

    def test_event_arn_extracted(self):
        result = parse_health_event(scheduled_change_event())
        assert result["eventArn"].startswith("arn:aws:health:")

    def test_service_extracted(self):
        result = parse_health_event(scheduled_change_event())
        assert result["service"] == "EKS"

    def test_status_code_extracted(self):
        result = parse_health_event(scheduled_change_event())
        assert result["statusCode"] == "upcoming"

    def test_description_extracted_from_english_entry(self):
        result = parse_health_event(scheduled_change_event())
        # The base event has an en_US description
        assert len(result["eventDescription"]) > 0

    def test_affected_account_normalized_to_list(self):
        """Single affectedAccount string is normalised to list."""
        result = parse_health_event(scheduled_change_event())
        assert result["affectedAccounts"] == ["123456789012"]

    def test_entities_normalised(self):
        result = parse_health_event(scheduled_change_event())
        assert len(result["affectedEntities"]) == 1
        entity = result["affectedEntities"][0]
        assert "entityValue" in entity
        assert "entityStatus" in entity


class TestParseAccountNotification:
    """Account-specific notification event."""

    def test_event_type_category(self):
        result = parse_health_event(account_notification_event())
        assert result["eventTypeCategory"] == "accountNotification"

    def test_personas_extracted(self):
        result = parse_health_event(account_notification_event())
        assert "account_owner" in result["personas"]

    def test_actionability_extracted(self):
        result = parse_health_event(account_notification_event())
        assert result["actionability"] == "ACTIONABLE"


class TestMultiPageEvent:
    """Multi-page event handling."""

    def test_page_and_total_pages(self):
        result = parse_health_event(multi_page_event(page=2, total_pages=3))
        assert result["page"] == 2
        assert result["totalPages"] == 3

    def test_communication_id_extracted(self):
        result = parse_health_event(multi_page_event())
        assert result["communicationId"] == "comm-abc-123"

    def test_affected_accounts_list(self):
        result = parse_health_event(multi_page_event())
        assert len(result["affectedAccounts"]) == 12  # 12 per page in fixture

    def test_page_defaults_to_1(self):
        """Events without page/totalPages default to page 1 of 1."""
        from tests.unit.intake.fixtures.health_event_fixtures import _base_event
        result = parse_health_event(_base_event())
        assert result["page"] == 1
        assert result["totalPages"] == 1


class TestClosedEvent:
    """Closed event."""

    def test_status_closed(self):
        result = parse_health_event(closed_event())
        assert result["statusCode"] == "closed"

    def test_end_time_extracted(self):
        result = parse_health_event(closed_event())
        assert result["endTime"] == "2026-01-01T06:00:00Z"

    def test_is_closed_returns_true(self):
        result = parse_health_event(closed_event())
        assert is_closed(result) is True

    def test_is_closed_returns_false_for_open(self):
        result = parse_health_event(scheduled_change_event())
        assert is_closed(result) is False


class TestUnknownFieldsPreservation:
    """Unknown fields are preserved in 'raw' key (R1.3, R1.7)."""

    def test_unknown_fields_in_raw(self):
        result = parse_health_event(event_with_unknown_fields())
        assert "futureField" in result["raw"]
        assert result["raw"]["futureField"] == "somevalue"

    def test_nested_unknown_field_preserved(self):
        result = parse_health_event(event_with_unknown_fields())
        assert result["raw"]["nestedFuture"] == {"a": 1, "b": 2}

    def test_raw_empty_when_no_unknown_fields(self):
        result = parse_health_event(scheduled_change_event())
        assert isinstance(result["raw"], dict)


class TestBareDetailInput:
    """Parser accepts bare detail dict without envelope."""

    def test_bare_detail_parsed(self):
        result = parse_health_event(bare_detail_event())
        assert result["service"] == "EC2"


class TestMalformedEvents:
    """Parser raises HealthEventParseError for invalid input."""

    def test_missing_required_field_raises(self):
        with pytest.raises(HealthEventParseError, match="Missing required fields"):
            parse_health_event(malformed_event_missing_arn())

    def test_non_dict_input_raises(self):
        with pytest.raises(HealthEventParseError):
            parse_health_event(malformed_event_not_dict())  # type: ignore[arg-type]

    def test_non_dict_detail_raises(self):
        with pytest.raises(HealthEventParseError):
            parse_health_event({"detail": "not-a-dict"})

    def test_empty_dict_raises(self):
        with pytest.raises(HealthEventParseError, match="Missing required fields"):
            parse_health_event({})


class TestIdempotencyKey:
    """idempotency_key returns eventArn#affectedAccount#lastUpdatedTime#page.

    Req §1b (working spec feat-devops-agent-enrichment, task -1a; also a
    master R2.1 wording correction): the key was previously
    eventArn#lastUpdatedTime, which collapses every account/page of one AWS
    update onto the SAME key. The org-view feed sends one message per
    (affectedAccount, page) for a single update, all sharing eventArn and
    lastUpdatedTime -- so the old key made message B for a second account
    look like a duplicate of message A and dropped it silently. See
    TestMultiAccountIdempotency below for the fixture that exercises this.
    """

    def test_key_format(self):
        result = parse_health_event(scheduled_change_event())
        key = idempotency_key(result)
        parts = key.split("#")
        assert len(parts) == 4
        assert parts[0] == result["eventArn"]
        assert parts[1] == "123456789012"  # affectedAccount from the fixture
        assert parts[2] == result["lastUpdatedTime"]
        assert parts[3] == "1"  # page, default 1

    def test_key_distinguishes_accounts_for_same_event_and_timestamp(self):
        """The defect this fixes: two accounts, same eventArn + lastUpdatedTime,
        must NOT collide on the same key."""
        msg_a = parse_health_event(org_view_message(account="111111111111"))
        msg_b = parse_health_event(org_view_message(account="222222222222"))
        assert msg_a["eventArn"] == msg_b["eventArn"]
        assert msg_a["lastUpdatedTime"] == msg_b["lastUpdatedTime"]
        assert idempotency_key(msg_a) != idempotency_key(msg_b)

    def test_key_distinguishes_pages_for_same_account(self):
        """Multi-page entity lists for one account (same lastUpdatedTime,
        page 1..N) must not collide either -- the second silent drop req §1b
        names."""
        page_1 = parse_health_event(org_view_message(page=1, total_pages=2))
        page_2 = parse_health_event(org_view_message(page=2, total_pages=2))
        assert idempotency_key(page_1) != idempotency_key(page_2)

    def test_key_empty_when_no_ts_or_account(self):
        key = idempotency_key({"eventArn": "arn:test", "lastUpdatedTime": ""})
        assert key == "arn:test###1"

    def test_key_uses_first_affected_account_when_no_singular_field(self):
        """Legacy affectedAccounts list (no singular affectedAccount) falls
        back to the first account in the list, so the key is still
        deterministic per message rather than empty."""
        result = parse_health_event(multi_page_event(page=1, total_pages=1))
        key = idempotency_key(result)
        first_account = result["affectedAccounts"][0]
        assert f"#{first_account}#" in key


class TestMultiAccountIdempotency:
    """Two org-view messages for the same eventArn/lastUpdatedTime but
    different affectedAccount are NOT duplicates of each other (req §1b).

    This is the exact scenario the pre-existing suite lacked, per the
    working spec: "Today's suite has no multi-account fixture -- this is
    why the defect survived live validation on a single-account sandbox."
    """

    def test_two_accounts_same_event_yield_distinct_keys(self):
        msg_a = parse_health_event(org_view_message(account="111111111111"))
        msg_b = parse_health_event(org_view_message(account="222222222222"))
        key_a = idempotency_key(msg_a)
        key_b = idempotency_key(msg_b)
        assert key_a != key_b, (
            "message B must not be treated as a duplicate of message A "
            "merely because they share eventArn + lastUpdatedTime"
        )

    def test_two_pages_same_account_yield_distinct_keys(self):
        page_1 = parse_health_event(org_view_message(page=1, total_pages=2))
        page_2 = parse_health_event(org_view_message(page=2, total_pages=2))
        assert idempotency_key(page_1) != idempotency_key(page_2)

    def test_same_account_and_page_resubmitted_is_still_a_true_duplicate(self):
        """Sanity check: the fix must not turn genuine retries into
        false-negatives -- an identical message still yields an identical
        key."""
        msg_1 = parse_health_event(org_view_message(account="111111111111", page=1))
        msg_2 = parse_health_event(org_view_message(account="111111111111", page=1))
        assert idempotency_key(msg_1) == idempotency_key(msg_2)
