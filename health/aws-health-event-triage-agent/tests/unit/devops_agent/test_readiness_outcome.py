# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.readiness_outcome."""

from __future__ import annotations

from src.devops_agent.readiness_outcome import summarize_readiness_outcome


class TestNoAnalysis:
    def test_none_input_returns_unverifiable(self):
        result = summarize_readiness_outcome(None)
        assert result == {
            "feasibility": "unverifiable",
            "blockers": [],
            "risk": "unknown",
            "rollback_available": None,
            "summary": "Readiness assessment completed but no analysis available",
        }

    def test_empty_string_input_returns_unverifiable(self):
        result = summarize_readiness_outcome("")
        assert result["feasibility"] == "unverifiable"
        assert result["risk"] == "unknown"


class TestReadyOutcome:
    def test_ready_no_blockers_rollback_available(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: READY\n"
            "BLOCKERS: NONE\n"
            "RISK: LOW\n"
            "ROLLBACK_AVAILABLE: YES\n\n"
            "All prerequisites satisfied; safe to proceed.\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "ready"
        assert result["blockers"] == []
        assert result["risk"] == "low"
        assert result["rollback_available"] is True
        assert "prerequisites" in result["summary"]


class TestBlockedOutcome:
    def test_blocked_with_multiple_blockers(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: BLOCKED\n"
            "BLOCKERS: outdated add-on version, unsupported API deprecated in target version\n"
            "RISK: HIGH\n"
            "ROLLBACK_AVAILABLE: NO\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "blocked"
        assert result["blockers"] == [
            "outdated add-on version",
            "unsupported API deprecated in target version",
        ]
        assert result["risk"] == "high"
        assert result["rollback_available"] is False


class TestNeedsRemediationOutcome:
    def test_needs_remediation_medium_risk(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: NEEDS_REMEDIATION\n"
            "BLOCKERS: pending patch\n"
            "RISK: MEDIUM\n"
            "ROLLBACK_AVAILABLE: YES\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "needs_remediation"
        assert result["blockers"] == ["pending patch"]
        assert result["risk"] == "medium"
        assert result["rollback_available"] is True


class TestMissingHeading:
    def test_missing_section_heading_falls_back_to_full_text_scan(self):
        # No "## Readiness Assessment" heading, but the key-value lines are
        # still present somewhere in the text -- should still parse.
        markdown = "Some preamble.\nFEASIBILITY: READY\nRISK: LOW\n"
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "ready"
        assert result["risk"] == "low"

    def test_no_recognizable_fields_returns_unverifiable(self):
        markdown = "## Readiness Assessment\n\nNo structured output produced.\n"
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "unverifiable"
        assert result["risk"] == "unknown"
        assert result["blockers"] == []
        assert result["rollback_available"] is None


class TestMalformedValues:
    def test_unrecognized_feasibility_value_degrades_to_unverifiable(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: MAYBE\n"
            "RISK: LOW\n"
            "ROLLBACK_AVAILABLE: YES\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "unverifiable"

    def test_unrecognized_risk_value_degrades_to_unknown(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: READY\n"
            "RISK: SEVERE\n"
            "ROLLBACK_AVAILABLE: YES\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["risk"] == "unknown"

    def test_unrecognized_rollback_value_degrades_to_none(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: READY\n"
            "RISK: LOW\n"
            "ROLLBACK_AVAILABLE: UNSURE\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["rollback_available"] is None

    def test_lowercase_values_are_normalized(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "feasibility: ready\n"
            "risk: low\n"
            "rollback_available: yes\n"
        )
        # Field names are matched case-sensitively (uppercase keys per contract);
        # lowercase keys should not match and fall back to defaults.
        result = summarize_readiness_outcome(markdown)
        assert result["feasibility"] == "unverifiable"


class TestBlockersParsing:
    def test_blockers_none_case_insensitive(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: READY\n"
            "BLOCKERS: none\n"
            "RISK: LOW\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["blockers"] == []

    def test_blockers_missing_field_defaults_to_empty(self):
        markdown = "## Readiness Assessment\n\nFEASIBILITY: READY\nRISK: LOW\n"
        result = summarize_readiness_outcome(markdown)
        assert result["blockers"] == []

    def test_blockers_strips_whitespace_around_items(self):
        markdown = (
            "## Readiness Assessment\n\n"
            "FEASIBILITY: BLOCKED\n"
            "BLOCKERS:   item one ,  item two  \n"
            "RISK: HIGH\n"
        )
        result = summarize_readiness_outcome(markdown)
        assert result["blockers"] == ["item one", "item two"]


class TestSummaryTruncation:
    def test_summary_is_truncated_to_500_chars(self):
        long_text = "x" * 1000
        markdown = f"## Readiness Assessment\n\nFEASIBILITY: READY\nRISK: LOW\n\n{long_text}\n"
        result = summarize_readiness_outcome(markdown)
        assert len(result["summary"]) <= 500
