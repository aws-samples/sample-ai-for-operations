# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.

"""Unit tests for src.devops_agent.outcome.summarize_investigation_outcome."""

from __future__ import annotations

from src.devops_agent.outcome import summarize_investigation_outcome

_IMPACT_ANALYSIS = """
## Summary

The AWS Health event affects the payments-api workload, which runs on the
listed EC2 instances without Multi-AZ redundancy in this Region.

## Key Findings

- **payments-api**: CRITICAL — instances will be stopped during the maintenance
  window with no failover. Affected resources: i-1234567890abcdef0. Redundancy: no.
- **checkout-worker**: LOW — Auto Scaling group will replace affected instances
  automatically. Affected resources: i-abcdef1234567890. Redundancy: yes.

## Answers to Your Questions

The payments-api workload directly uses the affected EC2 instances.

## Recommended Actions

| Priority | Action |
|----------|--------|
| **P1**   | Migrate payments-api to Multi-AZ before the maintenance window |
| **P2**   | Add a read replica for the checkout-worker database |

## Notification Routing

- **payments-team**: CRITICAL impact on payments-api. Contact via Slack.
"""

_NO_IMPACT_ANALYSIS = """
## Summary

The affected resources are not used by any workload in the topology; there is
no operational impact and no immediate operational action is required.
"""

_MALFORMED_ANALYSIS = "Just a plain sentence with no markdown headings at all."


class TestImpactDetected:
    def test_summary_extracted(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        assert "payments-api" in result["summary"]

    def test_impact_confirmed(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        assert result["impact"] == "confirmed"
        assert result["investigation_status"] == "IMPACT_DETECTED"

    def test_overall_severity_is_highest_finding(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        assert result["severity"] == "CRITICAL"

    def test_findings_parsed(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        descriptions = [f["description"] for f in result["findings"]]
        assert any("payments-api" in d for d in descriptions)
        assert any("checkout-worker" in d for d in descriptions)

    def test_finding_severities_parsed(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        severities = {f["severity"] for f in result["findings"]}
        assert "CRITICAL" in severities
        assert "LOW" in severities

    def test_recommendations_parsed_from_table(self):
        result = summarize_investigation_outcome(_IMPACT_ANALYSIS, "MEDIUM")
        assert len(result["recommendations"]) == 2
        assert result["recommendations"][0]["priority"] == "CRITICAL"  # P1
        assert result["recommendations"][1]["priority"] == "HIGH"  # P2


class TestNoImpact:
    def test_not_detected(self):
        result = summarize_investigation_outcome(_NO_IMPACT_ANALYSIS, "MEDIUM")
        assert result["impact"] == "not_detected"
        assert result["investigation_status"] == "NO_IMPACT"

    def test_severity_low_when_no_impact(self):
        result = summarize_investigation_outcome(_NO_IMPACT_ANALYSIS, "MEDIUM")
        assert result["severity"] == "LOW"

    def test_no_findings_or_recommendations(self):
        result = summarize_investigation_outcome(_NO_IMPACT_ANALYSIS, "MEDIUM")
        assert result["findings"] == []
        assert result["recommendations"] == []


class TestDegradedNoAnalysis:
    def test_analysis_unavailable_is_unverifiable(self):
        result = summarize_investigation_outcome(None, "HIGH")
        assert result["impact"] == "unverifiable"

    def test_analysis_unavailable_keeps_fallback_priority(self):
        result = summarize_investigation_outcome(None, "HIGH")
        assert result["severity"] == "HIGH"

    def test_empty_string_analysis_treated_as_unavailable(self):
        result = summarize_investigation_outcome("", "HIGH")
        assert result["impact"] == "unverifiable"

    def test_invalid_fallback_priority_defaults_to_medium(self):
        result = summarize_investigation_outcome(None, "NOT_A_REAL_SEVERITY")
        assert result["severity"] == "MEDIUM"


class TestMalformedAnalysis:
    def test_no_headings_does_not_raise(self):
        result = summarize_investigation_outcome(_MALFORMED_ANALYSIS, "MEDIUM")
        assert result["impact"] in ("confirmed", "not_detected")

    def test_no_headings_produces_some_summary(self):
        result = summarize_investigation_outcome(_MALFORMED_ANALYSIS, "MEDIUM")
        assert result["summary"]


class TestSeverityParsing:
    def test_leading_severity_word_extracted(self):
        analysis = """
## Key Findings

- **web-tier**: HIGH — degradation expected under peak load.
"""
        result = summarize_investigation_outcome(analysis, "MEDIUM")
        assert result["findings"][0]["severity"] == "HIGH"

    def test_non_leading_severity_word_not_falsely_matched(self):
        # Severity word appears mid-sentence, not leading -> falls back to
        # fallback_priority rather than incorrectly picking it up.
        analysis = """
## Key Findings

- **web-tier**: baseline load is LOW normally but escalates under failure.
"""
        result = summarize_investigation_outcome(analysis, "MEDIUM")
        assert result["findings"][0]["severity"] == "MEDIUM"
