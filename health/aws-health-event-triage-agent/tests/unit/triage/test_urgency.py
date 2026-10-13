# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.triage.urgency.compute_urgency."""

from __future__ import annotations

from datetime import date

import pytest

from src.triage.urgency import CRITICAL, HIGH, LOW, MEDIUM, compute_urgency

REF = date(2026, 1, 1)  # fixed reference date for all tests


class TestAlwaysLow:
    def test_informational_always_low(self):
        assert compute_urgency("2026-01-02", "INFORMATIONAL", now=REF) == LOW

    def test_unclassified_always_low(self):
        assert compute_urgency("2026-01-02", "UNCLASSIFIED", now=REF) == LOW

    def test_informational_no_deadline(self):
        assert compute_urgency(None, "INFORMATIONAL", now=REF) == LOW


class TestAlwaysCritical:
    def test_service_disruption_always_critical(self):
        assert compute_urgency(None, "SERVICE_DISRUPTION", now=REF) == CRITICAL

    def test_service_disruption_with_deadline(self):
        assert compute_urgency("2027-01-01", "SERVICE_DISRUPTION", now=REF) == CRITICAL


class TestNoDeadline:
    def test_breaking_change_no_deadline_is_low(self):
        assert compute_urgency(None, "BREAKING_CHANGE", now=REF) == LOW

    def test_security_no_deadline_is_low(self):
        assert compute_urgency(None, "SECURITY_RELATED", now=REF) == LOW


class TestThresholdBoundaries:
    """Default thresholds: critical ≤7d, high ≤30d, medium ≤90d, else low."""

    def test_exact_7_days_is_critical(self):
        dl = date(2026, 1, 8)  # REF + 7
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == CRITICAL

    def test_8_days_is_high(self):
        dl = date(2026, 1, 9)  # REF + 8
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == HIGH

    def test_exact_30_days_is_high(self):
        dl = date(2026, 1, 31)  # REF + 30
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == HIGH

    def test_31_days_is_medium(self):
        dl = date(2026, 2, 1)  # REF + 31
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == MEDIUM

    def test_exact_90_days_is_medium(self):
        dl = date(2026, 4, 1)  # REF + 90
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == MEDIUM

    def test_91_days_is_low(self):
        dl = date(2026, 4, 2)  # REF + 91
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == LOW

    def test_past_deadline_is_critical(self):
        dl = date(2025, 12, 31)  # 1 day before REF
        assert compute_urgency(str(dl), "BREAKING_CHANGE", now=REF) == CRITICAL


class TestCustomThresholds:
    def test_custom_thresholds_respected(self):
        thresholds = {"critical_days": 3, "high_days": 14, "medium_days": 60}
        dl_critical = date(2026, 1, 4)  # REF + 3
        dl_high = date(2026, 1, 10)    # REF + 9
        dl_medium = date(2026, 2, 1)   # REF + 31
        dl_low = date(2026, 3, 5)      # REF + 63

        assert compute_urgency(str(dl_critical), "BREAKING_CHANGE", now=REF, thresholds=thresholds) == CRITICAL
        assert compute_urgency(str(dl_high), "BREAKING_CHANGE", now=REF, thresholds=thresholds) == HIGH
        assert compute_urgency(str(dl_medium), "BREAKING_CHANGE", now=REF, thresholds=thresholds) == MEDIUM
        assert compute_urgency(str(dl_low), "BREAKING_CHANGE", now=REF, thresholds=thresholds) == LOW


class TestInvalidDeadline:
    def test_unparseable_deadline_returns_low(self):
        assert compute_urgency("not-a-date", "BREAKING_CHANGE", now=REF) == LOW

    def test_empty_deadline_returns_low(self):
        assert compute_urgency("", "BREAKING_CHANGE", now=REF) == LOW
