# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Table-driven unit tests for src.devops_agent.gate.decide_investigation.

Covers policy x category x scope x status x counters x dedupe combinations
per master tasks.md Phase 1b's explicit test requirement (R12.2, R12.4,
R12.5, R12.8).
"""

from __future__ import annotations

import pytest

from src.devops_agent.gate import decide_investigation

_REGISTRY_ENTRY = {
    "agentSpaceId": "space-1",
    "allowedScopes": ["ACCOUNT_SPECIFIC", "PUBLIC"],
    "allowedAccountNotificationCodes": ["AWS_EKS_CLUSTER_HEALTH_ISSUE"],
    "incidentCapPerMonth": 10,
}

_NOT_DUPLICATE = {"duplicate": False, "existing_investigation_id": None}
_UNDER_CAP = {"incident_count_this_month": 0, "cap": 10}


def _event(**overrides) -> dict:
    base = {
        "eventArn": "arn:aws:health:us-east-1::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/id",
        "eventTypeCategory": "issue",
        "statusCode": "open",
        "eventScopeCode": "ACCOUNT_SPECIFIC",
        "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
    }
    base.update(overrides)
    return base


class TestNoRegistry:
    def test_no_matching_agent_space_skips(self):
        result = decide_investigation(_event(), None, _UNDER_CAP, _NOT_DUPLICATE)
        assert result["trigger"] is False
        assert result["skip_kind"] == "no_registry"


class TestCategoryStatusEligibility:
    def test_open_issue_is_eligible(self):
        result = decide_investigation(_event(), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE)
        assert result["trigger"] is True
        assert result["skip_kind"] is None

    def test_closed_issue_not_eligible(self):
        result = decide_investigation(
            _event(statusCode="closed"), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_upcoming_issue_not_eligible(self):
        result = decide_investigation(
            _event(statusCode="upcoming"), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_scheduled_change_never_eligible(self):
        result = decide_investigation(
            _event(eventTypeCategory="scheduledChange"), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_account_notification_on_allow_list_eligible(self):
        result = decide_investigation(
            _event(
                eventTypeCategory="accountNotification",
                eventTypeCode="AWS_EKS_CLUSTER_HEALTH_ISSUE",
                statusCode="open",
            ),
            _REGISTRY_ENTRY,
            _UNDER_CAP,
            _NOT_DUPLICATE,
        )
        assert result["trigger"] is True

    def test_account_notification_not_on_allow_list_not_eligible(self):
        result = decide_investigation(
            _event(eventTypeCategory="accountNotification", eventTypeCode="SOME_OTHER_CODE"),
            _REGISTRY_ENTRY,
            _UNDER_CAP,
            _NOT_DUPLICATE,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_account_notification_open_not_required(self):
        # accountNotification eligibility does not require statusCode == open
        # per R12.2's category+code condition (only 'issue' requires open).
        result = decide_investigation(
            _event(
                eventTypeCategory="accountNotification",
                eventTypeCode="AWS_EKS_CLUSTER_HEALTH_ISSUE",
                statusCode="closed",
            ),
            _REGISTRY_ENTRY,
            _UNDER_CAP,
            _NOT_DUPLICATE,
        )
        assert result["trigger"] is True


class TestScopeEligibility:
    def test_scope_not_in_allow_list_skipped(self):
        registry_entry = {**_REGISTRY_ENTRY, "allowedScopes": ["ACCOUNT_SPECIFIC"]}
        result = decide_investigation(
            _event(eventScopeCode="PUBLIC"), registry_entry, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_scope_none_not_in_default_allow_list_skipped(self):
        result = decide_investigation(
            _event(eventScopeCode="NONE"), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is False

    def test_missing_allowed_scopes_falls_back_to_default(self):
        registry_entry = {k: v for k, v in _REGISTRY_ENTRY.items() if k != "allowedScopes"}
        result = decide_investigation(
            _event(eventScopeCode="PUBLIC"), registry_entry, _UNDER_CAP, _NOT_DUPLICATE
        )
        assert result["trigger"] is True


class TestDuplicateCheck:
    def test_duplicate_skips_trigger(self):
        dedupe = {"duplicate": True, "existing_investigation_id": "health-ec2-123-abcd1234"}
        result = decide_investigation(_event(), _REGISTRY_ENTRY, _UNDER_CAP, dedupe)
        assert result["trigger"] is False
        assert result["skip_kind"] == "duplicate"
        assert "health-ec2-123-abcd1234" in result["reason"]


class TestCapEnforcement:
    def test_cap_reached_skips_trigger(self):
        counters = {"incident_count_this_month": 10, "cap": 10}
        result = decide_investigation(_event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE)
        assert result["trigger"] is False
        assert result["skip_kind"] == "cap_exceeded"

    def test_cap_exceeded_skips_trigger(self):
        counters = {"incident_count_this_month": 15, "cap": 10}
        result = decide_investigation(_event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE)
        assert result["trigger"] is False
        assert result["skip_kind"] == "cap_exceeded"

    def test_under_cap_triggers(self):
        counters = {"incident_count_this_month": 9, "cap": 10}
        result = decide_investigation(_event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE)
        assert result["trigger"] is True


class TestGateOrderPrecedence:
    """Confirms skip_kind precedence: no_registry > not_eligible > duplicate > cap_exceeded."""

    def test_not_eligible_beats_duplicate_and_cap(self):
        dedupe = {"duplicate": True, "existing_investigation_id": "x"}
        counters = {"incident_count_this_month": 10, "cap": 10}
        result = decide_investigation(
            _event(statusCode="closed"), _REGISTRY_ENTRY, counters, dedupe
        )
        assert result["skip_kind"] == "not_eligible"

    def test_duplicate_beats_cap(self):
        dedupe = {"duplicate": True, "existing_investigation_id": "x"}
        counters = {"incident_count_this_month": 10, "cap": 10}
        result = decide_investigation(_event(), _REGISTRY_ENTRY, counters, dedupe)
        assert result["skip_kind"] == "duplicate"


@pytest.mark.parametrize(
    "category,status,scope,code,expect_trigger",
    [
        ("issue", "open", "ACCOUNT_SPECIFIC", "X", True),
        ("issue", "open", "PUBLIC", "X", True),
        ("issue", "open", "NONE", "X", False),
        ("issue", "closed", "ACCOUNT_SPECIFIC", "X", False),
        ("issue", "upcoming", "ACCOUNT_SPECIFIC", "X", False),
        ("scheduledChange", "open", "ACCOUNT_SPECIFIC", "X", False),
        ("accountNotification", "open", "ACCOUNT_SPECIFIC", "AWS_EKS_CLUSTER_HEALTH_ISSUE", True),
        ("accountNotification", "open", "ACCOUNT_SPECIFIC", "OTHER", False),
        ("investigation", "open", "ACCOUNT_SPECIFIC", "X", False),
    ],
)
def test_category_scope_status_code_matrix(category, status, scope, code, expect_trigger):
    event = _event(eventTypeCategory=category, statusCode=status, eventScopeCode=scope, eventTypeCode=code)
    result = decide_investigation(event, _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE)
    assert result["trigger"] is expect_trigger


# ---------------------------------------------------------------------------
# Task 3 (working spec feat-devops-agent-enrichment, design §3.2): the
# kind="enrichment" eligibility rule for deadline-class events. Extends the
# matrix above with the enrichment-kind rows rather than duplicating a
# parallel matrix, since scope/dedupe/cap logic (rows 3-5 of the gate order)
# is identical for both kinds and is already covered by the classes above.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "classification,expect_trigger",
    [
        ("BREAKING_CHANGE", True),
        ("SECURITY_RELATED", True),
        ("COST_IMPLICATION", True),
        ("INFORMATIONAL", False),
        ("SERVICE_DISRUPTION", False),
        ("UNCLASSIFIED", False),
        ("", False),
    ],
)
def test_enrichment_kind_classification_matrix(classification, expect_trigger):
    # scheduledChange/accountNotification category+status are irrelevant
    # for kind="enrichment" -- only classification gates eligibility, per
    # design §3.2. Using a scheduledChange event here deliberately proves
    # that: it would be ineligible under kind="incident" (see the
    # scheduledChange row in the matrix above), but is eligible here purely
    # on classification.
    event = _event(eventTypeCategory="scheduledChange", statusCode="upcoming")
    result = decide_investigation(
        event, _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE, kind="enrichment", classification=classification
    )
    assert result["trigger"] is expect_trigger


class TestEnrichmentKindGating:
    def test_no_registry_still_skips_first(self):
        result = decide_investigation(
            _event(), None, _UNDER_CAP, _NOT_DUPLICATE, kind="enrichment", classification="BREAKING_CHANGE"
        )
        assert result["skip_kind"] == "no_registry"

    def test_scope_not_allowed_skips_even_when_classification_eligible(self):
        registry_entry = {**_REGISTRY_ENTRY, "allowedScopes": ["ACCOUNT_SPECIFIC"]}
        result = decide_investigation(
            _event(eventScopeCode="PUBLIC"),
            registry_entry,
            _UNDER_CAP,
            _NOT_DUPLICATE,
            kind="enrichment",
            classification="BREAKING_CHANGE",
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_duplicate_skips_even_when_classification_eligible(self):
        dedupe = {"duplicate": True, "existing_investigation_id": "x"}
        result = decide_investigation(
            _event(), _REGISTRY_ENTRY, _UNDER_CAP, dedupe, kind="enrichment", classification="BREAKING_CHANGE"
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "duplicate"

    def test_cap_exceeded_skips_even_when_classification_eligible(self):
        counters = {"incident_count_this_month": 10, "cap": 10}
        result = decide_investigation(
            _event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE, kind="enrichment", classification="BREAKING_CHANGE"
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "cap_exceeded"

    def test_enrichment_and_incident_share_the_same_cap_and_dedupe(self):
        """req E4.5: enrichment does NOT get a separate cap/dedupe record --
        both kinds gate against the SAME counters/dedupe_result the caller
        supplies (this is asserted structurally: the function takes no
        kind-specific counters/dedupe parameter at all)."""
        counters = {"incident_count_this_month": 5, "cap": 10}
        incident_result = decide_investigation(_event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE)
        enrichment_result = decide_investigation(
            _event(), _REGISTRY_ENTRY, counters, _NOT_DUPLICATE, kind="enrichment", classification="BREAKING_CHANGE"
        )
        assert incident_result["trigger"] is True
        assert enrichment_result["trigger"] is True

    def test_default_kind_is_incident_unchanged(self):
        """Backward compatibility: callers that don't pass kind at all keep
        today's incident-gate behaviour exactly (existing callers,
        pre-task-6, never pass kind or classification)."""
        result_no_kind = decide_investigation(_event(), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE)
        result_explicit_incident = decide_investigation(
            _event(), _REGISTRY_ENTRY, _UNDER_CAP, _NOT_DUPLICATE, kind="incident"
        )
        assert result_no_kind == result_explicit_incident
