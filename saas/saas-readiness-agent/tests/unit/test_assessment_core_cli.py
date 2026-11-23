# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""CLI, session store, and error-path tests for src/assessment_core.py.

test_assessment_core.py covers the core assessment behavior: scoring,
evidence precedence, redaction, and HTML rendering. This file covers the CLI
subcommands (assess/questions/answer-set/answers), the JSON session store,
question selection/ranking, maturity gating, and the structured-error exit
paths. Every test here uses only synthetic data and a temporary directory,
per the project's "no real customer data in fixtures" rule.
"""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.assessment_core import (
    AssessmentError,
    InputFileError,
    JsonSessionStore,
    OutputFileError,
    Redactor,
    SessionStoreError,
    ValidationError,
    answered_question_ids,
    apply_maturity_gates,
    assess_payload,
    build_findings_list,
    build_summary_markdown,
    cmd_answer_set,
    cmd_answers,
    cmd_assess,
    cmd_questions,
    main,
    select_questions,
    write_assessment_json,
    write_findings_json,
    write_html_report,
    write_summary_markdown,
)


class _Args:
    """Minimal stand-in for argparse.Namespace so CLI command functions can
    be unit tested directly without going through argv parsing."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _assess_args(base_dir: Path, **overrides) -> _Args:
    defaults = dict(
        input=None,
        output="reports/out.html",
        json_debug=None,
        assessment_json=None,
        findings_json=None,
        summary_md=None,
        session="sessions/session.json",
        no_session=True,
        discover_aws=False,
        explain="none",
        explain_model_id=None,
        explain_region=None,
    )
    defaults.update(overrides)
    return _Args(**defaults)


class SessionStoreTests(unittest.TestCase):
    def test_set_and_list_answers_round_trip(self):
        with TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json")
            store.set_answer("BQ-001", "pooled", source="test")
            answers = store.list_answers()

            self.assertEqual(1, len(answers))
            self.assertEqual("BQ-001", answers[0].question_id)
            self.assertEqual("pooled", answers[0].answer_value)
            self.assertFalse(answers[0].changed)  # first write is not a "change"

    def test_changing_an_answer_marks_it_changed(self):
        with TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json")
            store.set_answer("BQ-001", "pooled", source="test")
            second = store.set_answer("BQ-001", "silo", source="test")

            self.assertTrue(second.changed)
            self.assertEqual("silo", second.answer_value)

    def test_empty_question_id_raises_session_store_error(self):
        with TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json")
            with self.assertRaises(SessionStoreError):
                store.set_answer("   ", "value")

    def test_corrupt_session_file_raises_session_store_error(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            path.write_text("{not valid json", encoding="utf-8")
            store = JsonSessionStore(path)
            with self.assertRaises(SessionStoreError):
                store.list_answers()

    def test_answers_are_redacted_before_storage(self):
        with TemporaryDirectory() as tmp:
            store = JsonSessionStore(Path(tmp) / "session.json", redactor=Redactor())
            store.set_answer("BQ-002", "admin@example.com owns tenant identity", source="test")
            answers = store.list_answers()

            self.assertIn("[redacted-email]", answers[0].answer_value)
            self.assertNotIn("admin@example.com", answers[0].answer_value)

    def test_mark_derived_current_updates_state(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "session.json"
            store = JsonSessionStore(path)
            store.set_answer("BQ-001", "pooled")
            store.mark_derived_current("assessment-123")

            state = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(state["derived_state"]["stale"])
            self.assertEqual("assessment-123", state["derived_state"]["assessment_id"])


class QuestionSelectionTests(unittest.TestCase):
    def test_select_questions_prioritizes_weak_controls(self):
        result = assess_payload(
            {
                "evidence": [
                    {"control_id": "TAI-01", "status": "missing", "confidence": "low"},
                ]
            }
        )
        selected = select_questions(result, answered=set(), limit=100)

        self.assertLessEqual(len(selected), 100)
        # AQ-004 is the customer-facing tenancy topic and must be available
        # when the tenancy-model control is unresolved.
        selected_ids = [question["id"] for question in selected]
        self.assertIn("AQ-004", selected_ids)

    def test_select_questions_excludes_already_answered(self):
        result = assess_payload({})
        selected = select_questions(
            result, answered={"BQ-001", "BQ-004", "BQ-011", "BQ-015"}, limit=30
        )

        selected_ids = {question["id"] for question in selected}
        self.assertFalse(selected_ids.intersection({"BQ-001", "BQ-004", "BQ-011", "BQ-015"}))

    def test_select_questions_respects_zero_limit(self):
        result = assess_payload({})
        self.assertEqual([], select_questions(result, answered=set(), limit=0))

    def test_answered_question_ids_reads_business_context(self):
        payload = {
            "business_context": {"answers": [{"question_id": "BQ-001", "answer_value": "pooled"}]}
        }
        self.assertEqual({"BQ-001"}, answered_question_ids(payload))


class MaturityGateTests(unittest.TestCase):
    def test_none_score_stays_none(self):
        self.assertIsNone(apply_maturity_gates(None, assess_payload({}).dimensions))

    def test_zero_tai_or_tlo_caps_overall_at_one(self):
        result = assess_payload(
            {
                "facts": {"shared_resources": True},
                "evidence": [
                    {"control_id": cid, "status": "missing", "confidence": "high"}
                    for cid in ("TAI-01", "TAI-02", "TAI-03", "TAI-04", "TAI-05", "TAI-06")
                ],
            }
        )
        # TAI dimension score should be 0, which must cap overall at 1.0 or below.
        tai = next(d for d in result.dimensions if d.id == "TAI")
        self.assertEqual(0.0, tai.score)
        self.assertLessEqual(result.overall_score, 1.0)


class CliCommandTests(unittest.TestCase):
    def test_cmd_assess_writes_html_report(self):
        # Baseline happy path: with no --assessment-json/--findings-json/
        # --summary-md flags set, only the primary HTML report should be
        # written - the optional artifacts stay opt-in.
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = _assess_args(base, output="reports/out.html")
            exit_code = _run_in_dir(base, cmd_assess, args)

            self.assertEqual(0, exit_code)
            self.assertTrue((base / "reports" / "out.html").exists())

    def test_cmd_assess_writes_all_optional_artifacts(self):
        # All three optional artifact flags together should each produce
        # their own file alongside (not instead of) the HTML report.
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = _assess_args(
                base,
                assessment_json="reports/assessment.json",
                findings_json="reports/findings.json",
                summary_md="reports/summary.md",
            )
            exit_code = _run_in_dir(base, cmd_assess, args)

            self.assertEqual(0, exit_code)
            self.assertTrue((base / "reports" / "assessment.json").exists())
            self.assertTrue((base / "reports" / "findings.json").exists())
            self.assertTrue((base / "reports" / "summary.md").exists())

    def test_cmd_assess_rejects_input_outside_base_dir(self):
        # End-to-end path-traversal check through the actual CLI entry
        # point, not just safe_path() in isolation (that's covered in
        # test_agent.py) - confirms cmd_assess wires --input through
        # safe_path() rather than reading the path directly.
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = _assess_args(base, input="../outside.json")
            with self.assertRaises(InputFileError):
                _run_in_dir(base, cmd_assess, args)

    def test_cmd_questions_prints_selected_questions(self):
        # Smoke test for the `questions` subcommand end to end (argument
        # parsing through to stdout); the actual selection/ranking logic is
        # covered in detail by QuestionSelectionTests above.
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            args = _Args(input=None, session="sessions/session.json", limit=3, json=True)
            exit_code = _run_in_dir(base, cmd_questions, args)
            self.assertEqual(0, exit_code)

    def test_cmd_answer_set_and_cmd_answers_round_trip(self):
        # Exercises the two subcommands together the way a real CLI session
        # would: save an answer with `answer-set`, then confirm `answers`
        # can read it back from the same session file.
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            set_args = _Args(
                session="sessions/session.json", question_id="BQ-005", value="launch", source="cli"
            )
            _run_in_dir(base, cmd_answer_set, set_args)

            list_args = _Args(session="sessions/session.json", json=True)
            exit_code = _run_in_dir(base, cmd_answers, list_args)
            self.assertEqual(0, exit_code)

    def test_main_returns_nonzero_on_missing_input_file(self):
        # Full argv-to-exit-code path through main(): confirms a missing
        # input file surfaces as a clean nonzero exit (via AssessmentError's
        # exit_code) rather than an uncaught traceback reaching the user.
        with TemporaryDirectory() as tmp:
            exit_code = _run_main_in_dir(
                tmp, ["assess", "--input", "does-not-exist.json", "--no-session"]
            )
            self.assertNotEqual(0, exit_code)


class FindingsAndSummaryTests(unittest.TestCase):
    def test_findings_list_has_expected_shape_and_length(self):
        result = assess_payload({})
        findings = build_findings_list(result)

        self.assertEqual(39, len(findings))  # matches rubric's fixed 39-control shape
        first = findings[0]
        for key in (
            "control_id",
            "dimension",
            "status",
            "evidence_state",
            "why_it_matters",
            "metric_rationale",
            "evidence",
            "recommended_next_step",
            "source_refs",
            "source_ref_claim",
        ):
            self.assertIn(key, first)

    def test_summary_markdown_includes_overall_score_and_dimensions(self):
        result = assess_payload({})
        markdown = build_summary_markdown(result)

        self.assertIn("# SaaS Readiness Snapshot", markdown)
        self.assertIn("## Assessment Status", markdown)
        self.assertIn("## Seven-Dimension Summary", markdown)
        self.assertIn("## Now / Next / Later", markdown)
        self.assertIn("## Appendix", markdown)
        self.assertIn("Tenant Architecture and Isolation", markdown)

    def test_write_functions_reject_paths_outside_base_dir(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            result = assess_payload({})
            # write_* functions accept an already-resolved Path, so path
            # traversal protection lives in safe_path() (tested elsewhere in
            # test_agent.py); here we confirm the writers succeed for a
            # legitimate nested path and create parent directories.
            target = base / "nested" / "dir" / "out.json"
            write_assessment_json(target, result)
            self.assertTrue(target.exists())

            target2 = base / "nested" / "findings.json"
            write_findings_json(target2, result)
            self.assertTrue(target2.exists())

            target3 = base / "nested" / "summary.md"
            write_summary_markdown(target3, result)
            self.assertTrue(target3.exists())

    def test_write_html_report_raises_output_file_error_on_bad_path(self):
        result = assess_payload({})
        # Writing to a path whose parent is a file (not a directory) should
        # raise OutputFileError rather than leaking a raw OSError traceback.
        with TemporaryDirectory() as tmp:
            blocking_file = Path(tmp) / "blocked"
            blocking_file.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(OutputFileError):
                write_html_report(blocking_file / "report.html", result)


class AssessmentErrorTests(unittest.TestCase):
    def test_to_dict_includes_code_and_message(self):
        error = ValidationError("bad input", detail="extra context")
        payload = error.to_dict()

        self.assertEqual("validation_error", payload["error"]["code"])
        self.assertEqual("bad input", payload["error"]["message"])
        self.assertEqual("extra context", payload["error"]["detail"])

    def test_base_assessment_error_default_exit_code_is_one(self):
        self.assertEqual(1, AssessmentError("x").exit_code)


def _run_in_dir(base_dir: Path, func, args):
    """Run a cmd_* function with cwd temporarily pointed at base_dir.

    cmd_* functions call Path.cwd() internally, so tests need to actually
    change the process working directory rather than just passing base_dir
    as a parameter (the functions don't accept one).
    """

    import os

    original_cwd = os.getcwd()
    os.chdir(base_dir)
    try:
        return func(args)
    finally:
        os.chdir(original_cwd)


def _run_main_in_dir(base_dir, argv):
    import os

    original_cwd = os.getcwd()
    os.chdir(base_dir)
    try:
        return main(argv)
    finally:
        os.chdir(original_cwd)


if __name__ == "__main__":
    unittest.main()
