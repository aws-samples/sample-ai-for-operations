# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.tools.normalize_dates."""

from __future__ import annotations

import pytest

from src.tools.normalize_dates import normalize_dates


class TestIso8601Input:
    def test_iso_date_returned_as_is(self):
        result = normalize_dates("The deadline is 2026-09-30.")
        assert any(r["isoDate"] == "2026-09-30" for r in result)

    def test_iso_date_phrase_preserved(self):
        result = normalize_dates("2026-09-30")
        assert result[0]["phrase"] == "2026-09-30"


class TestNaturalLanguageDates:
    def test_month_day_year(self):
        result = normalize_dates("Your resources will be affected after June 30, 2026.")
        assert len(result) >= 1
        assert result[0]["isoDate"] == "2026-06-30"

    def test_month_day_ordinal(self):
        result = normalize_dates("Action required by October 31st, 2026.")
        assert any(r["isoDate"] == "2026-10-31" for r in result)

    def test_day_month_year(self):
        result = normalize_dates("Before 1 September 2026.")
        assert any(r["isoDate"] == "2026-09-01" for r in result)

    def test_multiple_dates_extracted(self):
        result = normalize_dates(
            "Charges begin June 1, 2026 and auto-upgrade occurs September 1, 2026."
        )
        iso_dates = {r["isoDate"] for r in result}
        assert "2026-06-01" in iso_dates
        assert "2026-09-01" in iso_dates

    def test_deduplication(self):
        result = normalize_dates("June 30, 2026 ... June 30, 2026")
        iso_dates = [r["isoDate"] for r in result if r["isoDate"] == "2026-06-30"]
        assert len(iso_dates) == 1


class TestEdgeCases:
    def test_empty_string_returns_empty(self):
        assert normalize_dates("") == []

    def test_none_returns_empty(self):
        assert normalize_dates(None) == []  # type: ignore[arg-type]

    def test_no_dates_returns_empty(self):
        assert normalize_dates("This event requires immediate attention.") == []

    def test_unparseable_phrase_skipped(self):
        result = normalize_dates("No date here at all, just text.")
        assert result == []
