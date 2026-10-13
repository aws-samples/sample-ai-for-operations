# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.digest.format_digest.format_digest."""

from __future__ import annotations

import pytest

from src.digest.format_digest import format_digest


def _event(**overrides) -> dict:
    base = {
        "eventArn": "arn:aws:health:us-east-1::event/EKS/TEST/001",
        "service": "EKS",
        "eventTypeCode": "AWS_EKS_PLANNED_LIFECYCLE_EVENT",
        "eventTypeCategory": "scheduledChange",
        "statusCode": "upcoming",
        "affectedAccounts": ["123456789012"],
        "classification": "INFORMATIONAL",
        "deadline": None,
    }
    base.update(overrides)
    return base


class TestEmptyDigest:
    def test_no_events_returns_empty_digest(self):
        result = format_digest([], since="2026-01-01T00:00:00Z")
        assert result["generated_at_event_count"] == 0
        assert "No digest-disposition events" in result["text"]

    def test_no_events_included_arns_empty(self):
        result = format_digest([])
        assert result["included_event_arns"] == []


class TestGrouping:
    def test_same_family_grouped_together(self):
        events = [
            _event(eventArn="arn:1", affectedAccounts=["111111111111"]),
            _event(eventArn="arn:2", affectedAccounts=["222222222222"]),
        ]
        result = format_digest(events)
        assert len(result["families"]) == 1
        assert len(result["families"][0]["events"]) == 2

    def test_different_families_separated(self):
        events = [
            _event(eventArn="arn:1", service="EKS", eventTypeCode="AWS_EKS_A"),
            _event(eventArn="arn:2", service="RDS", eventTypeCode="AWS_RDS_B"),
        ]
        result = format_digest(events)
        assert len(result["families"]) == 2

    def test_account_count_deduplicated(self):
        events = [
            _event(eventArn="arn:1", affectedAccounts=["111111111111", "222222222222"]),
            _event(eventArn="arn:2", affectedAccounts=["111111111111"]),  # overlapping account
        ]
        result = format_digest(events)
        assert result["families"][0]["account_count"] == 2

    def test_families_sorted_deterministically(self):
        events = [
            _event(eventArn="arn:1", service="RDS", eventTypeCode="Z"),
            _event(eventArn="arn:2", service="EKS", eventTypeCode="A"),
        ]
        result = format_digest(events)
        keys = [f["family_key"] for f in result["families"]]
        assert keys == sorted(keys)


class TestPrecheckResultsIncluded:
    def test_precheck_result_appears_in_family(self):
        events = [
            _event(eventArn="arn:1", precheckResult={"result": "not_checked", "reason": "no K8s access"}),
        ]
        result = format_digest(events)
        assert len(result["families"][0]["precheck_results"]) == 1
        assert result["families"][0]["precheck_results"][0]["result"] == "not_checked"

    def test_not_checked_visible_in_text(self):
        events = [
            _event(eventArn="arn:1", precheckResult={"result": "not_checked", "reason": "no K8s access"}),
        ]
        result = format_digest(events)
        assert "not_checked" in result["text"]
        assert "no K8s access" in result["text"]

    def test_no_precheck_result_key_omitted(self):
        events = [_event(eventArn="arn:1")]
        result = format_digest(events)
        assert result["families"][0]["precheck_results"] == []


class TestIncludedEventArns:
    def test_all_event_arns_tracked(self):
        events = [_event(eventArn="arn:1"), _event(eventArn="arn:2")]
        result = format_digest(events)
        assert set(result["included_event_arns"]) == {"arn:1", "arn:2"}


class TestTextRendering:
    def test_since_appears_in_text_when_provided(self):
        result = format_digest([_event()], since="2026-01-01T00:00:00Z")
        assert "2026-01-01T00:00:00Z" in result["text"]

    def test_since_omitted_when_none(self):
        result = format_digest([_event()], since=None)
        assert "Events since" not in result["text"]
