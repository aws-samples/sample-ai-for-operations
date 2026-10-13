# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Table-driven unit tests for src.devops_agent.readiness_gate.decide_readiness.

Covers registry enabled/disabled x impact status x classification family x
deadline in/out of horizon x prior-assessment empty/partial/full x
counters under/at cap, per master tasks.md Phase 5b's test requirement and
this working spec's design.md §3.
"""

from __future__ import annotations

from datetime import date

import pytest

from src.devops_agent.readiness_gate import decide_readiness

_TODAY = date(2026, 1, 1)

_REGISTRY_ENABLED = {
    "agentSpaceId": "space-1",
    "readinessEnabled": True,
    "readinessCapPerMonth": 10,
}
_REGISTRY_DISABLED = {**_REGISTRY_ENABLED, "readinessEnabled": False}

_UNDER_CAP = {"readiness_count_this_month": 0, "cap": 10}
_AT_CAP = {"readiness_count_this_month": 10, "cap": 10}

_NO_PRIOR = {"assessed_accounts": []}

_CONFIRMED_IMPACT = {
    "impact_status": "confirmed",
    "by_account": {"111111111111": {"resources": []}, "222222222222": {"resources": []}},
}
_NOT_DETECTED_IMPACT = {"impact_status": "not_detected", "by_account": {}}
_UNVERIFIABLE_IMPACT = {"impact_status": "unverifiable", "by_account": {}}


def _classification(**overrides) -> dict:
    base = {"classification": "BREAKING_CHANGE", "reason": "x" * 10, "deadline": "2026-02-01"}
    base.update(overrides)
    return base


class TestNoRegistry:
    def test_no_matching_agent_space_skips(self):
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, None, _UNDER_CAP, _NO_PRIOR, today=_TODAY
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "no_registry"


class TestDisabled:
    def test_readiness_disabled_skips(self):
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_DISABLED, _UNDER_CAP, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "disabled"


class TestImpactStatusNoLongerGatesEligibility:
    """Corrected 2026-09-28, working spec feat-devops-agent-enrichment E4.2
    / design §3.2, task 4. Before this fix, not_detected/unverifiable
    impact was asserted as 'not_eligible' -- that assertion is the
    behaviour this task removes: impact is discovered BY the readiness
    investigation now, not known before it, so gating on it made the
    question unreachable for exactly the events (uncovered accounts,
    dependent-locus events) that most need an answer. Every impact_status
    value is now equally eligible; only classification/deadline/horizon/
    prior-assessment/cap decide."""

    def test_confirmed_impact_still_eligible(self):
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is True

    def test_not_detected_impact_now_still_eligible(self):
        # by_account is empty for _NOT_DETECTED_IMPACT, so there is nothing
        # to assess -- the resulting skip is "already_assessed" (empty
        # accounts_to_assess), NOT "not_eligible". This distinguishes "the
        # question is ineligible to ask" from "there is nothing to ask it
        # about," which is the correct distinction now that impact_status
        # itself never blocks eligibility.
        result = decide_readiness(
            {}, _classification(), _NOT_DETECTED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "already_assessed"

    def test_unverifiable_impact_with_accounts_present_is_eligible(self):
        impact = {"impact_status": "unverifiable", "by_account": {"111111111111": {}}}
        result = decide_readiness(
            {}, _classification(), impact, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is True
        assert result["accounts_to_assess"] == ["111111111111"]

    def test_in_scope_unverified_impact_with_accounts_present_is_eligible(self):
        """The new dependent-locus status (req §1a) must not be treated
        specially here either -- readiness eligibility never reads
        impact_status at all after this fix."""
        impact = {"impact_status": "in_scope_unverified", "by_account": {"111111111111": {}}}
        result = decide_readiness(
            {}, _classification(), impact, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is True


class TestClassificationEligibility:
    def test_breaking_change_with_deadline_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="BREAKING_CHANGE", deadline="2026-02-01"),
            _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is True

    def test_security_related_with_deadline_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="SECURITY_RELATED", deadline="2026-02-01"),
            _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is True

    def test_breaking_change_without_deadline_not_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="BREAKING_CHANGE", deadline=None),
            _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_cost_implication_never_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="COST_IMPLICATION", deadline="2026-02-01"),
            _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_service_disruption_never_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="SERVICE_DISRUPTION", deadline="2026-02-01"),
            _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"


class TestDeadlineHorizon:
    def test_deadline_within_horizon_eligible(self):
        result = decide_readiness(
            {}, _classification(deadline="2026-03-01"), _CONFIRMED_IMPACT, _REGISTRY_ENABLED,
            _UNDER_CAP, _NO_PRIOR, horizon_days=90, today=_TODAY,
        )
        assert result["trigger"] is True

    def test_deadline_beyond_horizon_not_eligible(self):
        result = decide_readiness(
            {}, _classification(deadline="2027-01-01"), _CONFIRMED_IMPACT, _REGISTRY_ENABLED,
            _UNDER_CAP, _NO_PRIOR, horizon_days=90, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_deadline_in_the_past_not_eligible(self):
        result = decide_readiness(
            {}, _classification(deadline="2025-01-01"), _CONFIRMED_IMPACT, _REGISTRY_ENABLED,
            _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"

    def test_unparseable_deadline_not_eligible(self):
        result = decide_readiness(
            {}, _classification(deadline="not-a-date"), _CONFIRMED_IMPACT, _REGISTRY_ENABLED,
            _UNDER_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "not_eligible"


class TestPriorAssessment:
    def test_empty_prior_assessment_assesses_all_accounts(self):
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is True
        assert set(result["accounts_to_assess"]) == {"111111111111", "222222222222"}

    def test_partial_prior_assessment_assesses_only_new_accounts(self):
        prior = {"assessed_accounts": ["111111111111"]}
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, prior,
            today=_TODAY,
        )
        assert result["trigger"] is True
        assert result["accounts_to_assess"] == ["222222222222"]

    def test_full_prior_assessment_skips_as_already_assessed(self):
        prior = {"assessed_accounts": ["111111111111", "222222222222"]}
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, prior,
            today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "already_assessed"

    def test_status_only_update_same_accounts_never_retriggers(self):
        # A status-only update (e.g. upcoming -> open) produces the same
        # by_account key set as before -- simulated here by reusing
        # _CONFIRMED_IMPACT with a prior assessment that already covers
        # every account in it, proving the mechanism works by construction
        # rather than a separate "was this status-only" flag.
        prior = {"assessed_accounts": list(_CONFIRMED_IMPACT["by_account"].keys())}
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _UNDER_CAP, prior,
            today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "already_assessed"


class TestCapEnforcement:
    def test_cap_reached_skips_trigger(self):
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _AT_CAP, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is False
        assert result["skip_kind"] == "cap_exceeded"

    def test_under_cap_triggers(self):
        counters = {"readiness_count_this_month": 9, "cap": 10}
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, counters, _NO_PRIOR,
            today=_TODAY,
        )
        assert result["trigger"] is True


class TestGateOrderPrecedence:
    def test_disabled_beats_not_eligible(self):
        result = decide_readiness(
            {}, _classification(classification="COST_IMPLICATION"), _NOT_DETECTED_IMPACT,
            _REGISTRY_DISABLED, _AT_CAP, _NO_PRIOR, today=_TODAY,
        )
        assert result["skip_kind"] == "disabled"

    def test_already_assessed_beats_cap_exceeded(self):
        prior = {"assessed_accounts": list(_CONFIRMED_IMPACT["by_account"].keys())}
        result = decide_readiness(
            {}, _classification(), _CONFIRMED_IMPACT, _REGISTRY_ENABLED, _AT_CAP, prior,
            today=_TODAY,
        )
        assert result["skip_kind"] == "already_assessed"


@pytest.mark.parametrize(
    "readiness_enabled,impact_status,classification,deadline,expect_trigger",
    [
        (True, "confirmed", "BREAKING_CHANGE", "2026-02-01", True),
        (True, "confirmed", "SECURITY_RELATED", "2026-02-01", True),
        (False, "confirmed", "BREAKING_CHANGE", "2026-02-01", False),
        # not_detected/unverifiable/in_scope_unverified were asserted False
        # before the task 4 fix (impact_status used to gate eligibility) --
        # all now True: impact_status never gates eligibility, only
        # classification/deadline/horizon/prior-assessment/cap do, and
        # by_account still has an account present for these rows.
        (True, "not_detected", "BREAKING_CHANGE", "2026-02-01", True),
        (True, "unverifiable", "BREAKING_CHANGE", "2026-02-01", True),
        (True, "in_scope_unverified", "BREAKING_CHANGE", "2026-02-01", True),
        (True, "confirmed", "BREAKING_CHANGE", None, False),
        (True, "confirmed", "COST_IMPLICATION", "2026-02-01", False),
        (True, "confirmed", "INFORMATIONAL", "2026-02-01", False),
        (True, "confirmed", "BREAKING_CHANGE", "2027-06-01", False),
    ],
)
def test_eligibility_matrix(readiness_enabled, impact_status, classification, deadline, expect_trigger):
    registry_entry = {**_REGISTRY_ENABLED, "readinessEnabled": readiness_enabled}
    impact = {"impact_status": impact_status, "by_account": {"111111111111": {}}}
    result = decide_readiness(
        {}, _classification(classification=classification, deadline=deadline), impact,
        registry_entry, _UNDER_CAP, _NO_PRIOR, today=_TODAY,
    )
    assert result["trigger"] is expect_trigger
