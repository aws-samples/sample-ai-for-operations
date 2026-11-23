# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Tests for the deterministic scoring engine and CLI (src/assessment_core.py).

Covers core assessment behavior: scoring, evidence precedence, redaction, and
HTML rendering. See test_assessment_core_cli.py for CLI subcommand, session
store, and structured-error coverage, and test_agent.py for the Strands
agent's tool-delegation tests.
"""

import json
import tempfile
import threading
import unittest
from pathlib import Path

from src.assessment_core import (
    InputFileError,
    JsonSessionStore,
    Redactor,
    ValidationError,
    assess_payload,
    dimension_customer_explanation,
    render_html_report,
    safe_path,
)
from src.questions import QUESTIONS
from src.rubric import DIMENSIONS, all_controls

# Synthetic, access-key-shaped value used only to prove the Redactor removes
# access key IDs from reports. Assembled at runtime so the source file holds
# no key-shaped literal for secret scanners to flag.
FAKE_ACCESS_KEY_ID = "AKIA" + "1234567890ABCDEF"


def control(result, control_id):
    for dimension in result.dimensions:
        for item in dimension.controls:
            if item.id == control_id:
                return item
    raise AssertionError(f"Control {control_id} not found")


class AssessmentCoreTests(unittest.TestCase):
    def test_rubric_shape_is_complete(self):
        self.assertEqual(7, len(DIMENSIONS))
        self.assertEqual(39, len(all_controls()))
        self.assertEqual(14, len(QUESTIONS))

    def test_business_answers_become_control_evidence(self):
        result = assess_payload(
            {
                "business_context": {
                    "stage": "launch",
                    "target_segment": "B2B SMB",
                    "tenancy_model": "pooled",
                    "growth_pressure": "first production tenants",
                    "answers": [
                        {"question_id": "BQ-001", "answer_value": "pooled", "source": "test"},
                        {
                            "question_id": "BQ-004",
                            "answer_value": "manual",
                            "source": "test",
                        },
                    ],
                }
            }
        )

        self.assertEqual("partial", control(result, "TAI-01").status)
        self.assertIn("pooled", control(result, "TAI-01").evidence_summary)
        self.assertEqual("missing", control(result, "TLO-02").status)
        self.assertIn("manual", control(result, "TLO-02").evidence_summary)

    def test_missing_permission_is_unknown_not_missing(self):
        result = assess_payload({"facts": {"missing_permissions": ["ce:GetCostAndUsage"]}})

        item = control(result, "CAM-03")
        self.assertEqual("unknown", item.status)
        self.assertEqual("low", item.confidence)
        self.assertIn("ce:GetCostAndUsage", item.evidence_summary)

    def test_inspected_absent_signal_is_missing(self):
        result = assess_payload({"facts": {"signals": {"iac": {"inspected": True, "detected": False}}}})

        item = control(result, "DPA-01")
        self.assertEqual("missing", item.status)
        self.assertIn("no IaC", item.evidence_summary)

    def test_explicit_evidence_wins_over_inferred_evidence(self):
        result = assess_payload(
            {
                "facts": {
                    "services": ["ec2", "postgresql"],
                    "signals": {
                        "self_managed_database_on_ec2": {
                            "inspected": True,
                            "detected": True,
                            "engine": "PostgreSQL",
                            "tenant_isolation_detected": False,
                        }
                    },
                },
                "evidence": [
                    {
                        "control_id": "TAI-03",
                        "status": "met",
                        "confidence": "high",
                        "evidence_state": "confirmed",
                        "summary": "Reviewed data access layer enforces tenant context.",
                        "source": "test",
                    }
                ],
            }
        )

        item = control(result, "TAI-03")
        self.assertEqual("met", item.status)
        self.assertIn("Reviewed data access", item.evidence_summary)

    def test_ec2_hosted_database_is_first_class_signal(self):
        result = assess_payload(
            {
                "facts": {
                    "services": ["ec2", "postgresql"],
                    "signals": {
                        "self_managed_database_on_ec2": {
                            "inspected": True,
                            "detected": True,
                            "engine": "PostgreSQL",
                            "tenant_isolation_detected": False,
                            "tenant_metrics_detected": False,
                            "tenant_consumption_detected": False,
                        }
                    },
                }
            }
        )

        self.assertEqual("missing", control(result, "TAI-03").status)
        self.assertEqual("missing", control(result, "OOR-01").status)
        self.assertEqual("missing", control(result, "CAM-06").status)
        self.assertIn("security-group", control(result, "TAI-03").evidence_summary)
        self.assertIn("EC2/EBS", control(result, "CAM-06").evidence_summary)

    def test_ec2_hosted_database_engine_aliases_are_supported(self):
        for engine_name in ("Microsoft SQL Server", "Oracle Database", "MySQL", "MariaDB", "MongoDB", "DB2", "SAP HANA"):
            with self.subTest(engine_name=engine_name):
                result = assess_payload({"facts": {"services": ["ec2", engine_name]}})

                self.assertEqual("unknown", control(result, "TAI-03").status)
                self.assertIn("database", control(result, "TAI-03").evidence_summary)
                self.assertIn("EC2/EBS", control(result, "CAM-06").evidence_summary)

    def test_html_report_is_dark_human_readable_and_service_aware(self):
        sample = json.loads(Path("samples/minimal_assessment.json").read_text(encoding="utf-8"))
        html = render_html_report(assess_payload(sample))

        self.assertIn("<body>", html)
        self.assertIn("SaaS Readiness Snapshot", html)
        self.assertNotIn("SaaS " + "Pre" + "-Assessment", html)
        self.assertIn("background: var(--bg)", html)
        self.assertIn("Read This First", html)
        self.assertIn("Environment and Service Observations", html)
        self.assertIn("Self-managed database on EC2", html)
        self.assertNotRegex(html, r"[\U0001F300-\U0001FAFF]")

    def test_malformed_input_returns_structured_error_path(self):
        with self.assertRaises(ValidationError):
            assess_payload([])

    def test_redaction_and_path_validation(self):
        result = assess_payload(
            {
                "evidence": [
                    {
                        "control_id": "TAI-01",
                        "status": "partial",
                        "confidence": "medium",
                        "summary": (
                            "arn:aws:iam::123456789012:role/Admin admin@example.com "
                            + f"password=secret {FAKE_ACCESS_KEY_ID}"
                        ),
                    }
                ]
            },
            redactor=Redactor(),
        )
        html = render_html_report(result)

        self.assertNotIn("123456789012", html)
        self.assertNotIn("admin@example.com", html)
        self.assertNotIn("password=secret", html)
        self.assertNotIn(FAKE_ACCESS_KEY_ID, html)
        self.assertIn("[redacted-access-key-id]", html)
        self.assertIn("[redacted-arn]", html)
        self.assertIn("[redacted-email]", html)
        self.assertIn("password=[redacted-sensitive-value]", html)

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            self.assertTrue(str(safe_path(base, "reports/out.html", "output")).startswith(str(base.resolve())))
            with self.assertRaises(InputFileError):
                safe_path(base, "../outside.json", "input")


class AdaptiveQuestionAndCoverageTests(unittest.TestCase):
    """Regression tests for the evidence-first front-door experience."""

    def test_customer_asserted_answers_use_exact_closed_options(self):
        result = assess_payload(
            {
                "business_context": {
                    "answers": [
                        {"question_id": "BQ-001", "answer_value": "hybrid"},
                        {"question_id": "BQ-004", "answer_value": "manual"},
                        {
                            "question_id": "BQ-017",
                            "answer_value": "shared_filter_only",
                        },
                    ]
                }
            }
        )

        self.assertEqual("customer_asserted", control(result, "TAI-01").evidence_state)
        self.assertEqual("missing", control(result, "TLO-02").status)
        self.assertEqual("missing", control(result, "TAI-03").status)
        self.assertEqual("provisional", result.coverage.report_status)

    def test_answer_context_populates_named_business_fields(self):
        result = assess_payload(
            {
                "business_context": {
                    "answers": [
                        {"question_id": "BQ-001", "answer_value": "hybrid"},
                        {"question_id": "BQ-005", "answer_value": "scaling"},
                        {"question_id": "BQ-006", "answer_value": "enterprise"},
                        {"question_id": "BQ-007", "answer_value": "usage_based"},
                        {"question_id": "BQ-013", "answer_value": "tenant_scale"},
                    ]
                }
            }
        )

        self.assertEqual("hybrid", result.business_context.tenancy_model)
        self.assertEqual("scaling", result.business_context.stage)
        self.assertEqual("enterprise", result.business_context.target_segment)
        self.assertEqual("usage_based", result.business_context.pricing_model)
        self.assertEqual("tenant_scale", result.business_context.growth_pressure)

    def test_report_exposes_provisional_status_and_appendix(self):
        html = render_html_report(assess_payload({}))

        for heading in (
            "Assessment Status",
            "Provisional",
            "Evidence Coverage",
            "SaaS Maturity Profile",
            "Evidence Coverage by Dimension",
            "Now / Next / Later",
            "Primary Engagement Route",
            "Appendix",
            "Methodology",
            "Public AWS References",
        ):
            self.assertIn(heading, html)


    def test_baseline_requires_breadth_across_all_dimensions(self):
        evidence = [
            {
                "control_id": control_definition["id"],
                "status": "met",
                "confidence": "high",
                "evidence_state": "confirmed",
                "summary": "Reviewed synthetic evidence.",
                "source": "test",
            }
            for dimension_definition in DIMENSIONS
            for control_definition in dimension_definition["controls"]
        ]
        result = assess_payload({"evidence": evidence})

        self.assertEqual("baseline", result.coverage.report_status)
        self.assertEqual(39, result.coverage.assessed_controls)
        self.assertEqual(1.0, result.coverage.coverage_ratio)



class DimensionExplanationTests(unittest.TestCase):
    """Customer-facing score narratives must expose real evidence, not arithmetic."""

    def test_dimension_explanation_surfaces_strength_risk_gap_and_sources(self):
        result = assess_payload(
            {
                "evidence": [
                    {
                        "control_id": "TAI-01",
                        "status": "partial",
                        "confidence": "medium",
                        "summary": "Hybrid tenancy is documented but not verified against deployment.",
                        "source": "test",
                    },
                    {
                        "control_id": "TAI-03",
                        "status": "missing",
                        "confidence": "high",
                        "summary": "Shared data access lacks tenant-context enforcement.",
                        "source": "test",
                    },
                ]
            }
        )
        dimension = next(item for item in result.dimensions if item.id == "TAI")
        explanation = dimension_customer_explanation(dimension)

        self.assertIn("lacks tenant-context", explanation["summary"].lower())
        self.assertTrue(any("Hybrid tenancy" in item for item in explanation["partials"]))
        self.assertTrue(any("lacks tenant-context" in item for item in explanation["blockers"]))
        self.assertTrue(explanation["gaps"])
        self.assertTrue(explanation["source_ids"])

    def test_html_dimension_summary_exposes_evidence_sections(self):
        html = render_html_report(
            assess_payload(
                {
                    "evidence": [
                        {
                            "control_id": "TAI-01",
                            "status": "partial",
                            "summary": "Hybrid tenancy is documented.",
                            "source": "test",
                        },
                        {
                            "control_id": "TAI-03",
                            "status": "missing",
                            "summary": "Shared data access is not enforced.",
                            "source": "test",
                        },
                    ]
                }
            )
        )

        self.assertIn("Partial foundations", html)
        self.assertIn("What needs attention", html)
        self.assertIn("Still to validate", html)
        self.assertIn("AWS guidance", html)



class ReportVisualizationTests(unittest.TestCase):
    def test_profile_and_coverage_charts_expose_not_scored_dimensions_accessibly(self):
        html = render_html_report(assess_payload({}))

        self.assertIn('aria-labelledby="maturity-profile-title"', html)
        self.assertIn('aria-labelledby="evidence-coverage-chart-title"', html)
        self.assertIn('class="bar-unscored">Not scored', html)
        self.assertIn('class="coverage-unknown"', html)
        self.assertIn('aria-label="Tenant Architecture and Isolation: not scored', html)


class JsonSessionStoreConcurrencyTests(unittest.TestCase):
    """The model often saves several answers in one turn, so concurrent
    set_answer() calls must neither crash nor drop each other's answers."""

    WRITERS = 12

    def _save_concurrently(self, store, question_ids):
        barrier = threading.Barrier(len(question_ids))
        errors = []

        def save(question_id):
            barrier.wait()
            try:
                store.set_answer(question_id, f"value-{question_id}", "test")
            except Exception as exc:  # collected so the test reports every failure
                errors.append(exc)

        threads = [threading.Thread(target=save, args=(qid,)) for qid in question_ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        return errors

    def test_concurrent_answers_all_persist(self):
        question_ids = [f"BQ-{i:03d}" for i in range(1, self.WRITERS + 1)]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            errors = self._save_concurrently(JsonSessionStore(path, Redactor()), question_ids)

            self.assertEqual([], errors)
            reloaded = JsonSessionStore(path, Redactor())
            saved = {answer.question_id for answer in reloaded.list_answers()}
            self.assertEqual(set(question_ids), saved)

    def test_concurrent_writes_leave_no_temp_files(self):
        question_ids = [f"BQ-{i:03d}" for i in range(1, self.WRITERS + 1)]
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            self._save_concurrently(JsonSessionStore(path, Redactor()), question_ids)

            self.assertEqual(["session.json"], sorted(p.name for p in Path(temp_dir).iterdir()))
            json.loads(path.read_text(encoding="utf-8"))



if __name__ == "__main__":
    unittest.main()
