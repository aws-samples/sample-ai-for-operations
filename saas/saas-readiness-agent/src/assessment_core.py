# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Deterministic SaaS readiness scoring engine and CLI.

This is not the AI agent (see src/agent.py for that). This module has zero
Strands or Bedrock imports on purpose: it owns every score, status, and
confidence value the agent's tools report, so the agent's tools call into
this module's assess_payload() rather than computing anything themselves.

Static rubric content lives in rubric.py; everything that changes runtime
behavior (input handling, inference, scoring, reporting, and the standalone
`saas-readiness-assess` CLI) is here so reviewers can follow it without
jumping across many modules.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import threading
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from json import JSONDecodeError
from pathlib import Path
from typing import Any

try:
    from src.rubric import DIMENSIONS, MATURITY_SCALE, SOURCES
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from rubric import (  # type: ignore[import-not-found, no-redef]
        DIMENSIONS,
        MATURITY_SCALE,
        SOURCES,
    )

try:
    from src.questions import ANSWER_CONTROL_RULES
    from src.questions import QUESTIONS as ADAPTIVE_QUESTIONS
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from questions import (  # type: ignore[import-not-found, no-redef]
        ANSWER_CONTROL_RULES,
    )
    from questions import (  # type: ignore[import-not-found, no-redef]
        QUESTIONS as ADAPTIVE_QUESTIONS,
    )

try:
    from src.discovery import PERMISSION_CONTROL_MAP, run_aws_discovery
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from discovery import (  # type: ignore[import-not-found, no-redef]
        PERMISSION_CONTROL_MAP,
        run_aws_discovery,
    )

try:
    from src.explainer import ExplanationBundle, build_explainer
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from explainer import (  # type: ignore[import-not-found, no-redef]
        ExplanationBundle,
        build_explainer,
    )

try:
    from src.session_store import SessionAnswer, SessionStore
except ModuleNotFoundError:  # pragma: no cover - supports direct execution from src/
    from session_store import (  # type: ignore[import-not-found, no-redef]
        SessionAnswer,
        SessionStore,
    )


DEFAULT_OUTPUT_PATH = "reports/assessment.html"
DEFAULT_SESSION_PATH = "sessions/session.json"

VALID_STATUSES = {"met", "partial", "missing", "unknown", "not_applicable"}
VALID_CONFIDENCE = {"high", "medium", "low"}
VALID_EVIDENCE_STATES = {"confirmed", "suggestive", "sampled", "customer_asserted", "unknown"}

STATUS_SCORES: dict[str, float | None] = {
    "met": 1.0,
    "partial": 0.5,
    "missing": 0.0,
    "unknown": None,
    "not_applicable": None,
}

CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}
BASELINE_COVERAGE_THRESHOLD = 0.70

# PERMISSION_CONTROL_MAP and the minimum/enhanced read-only action lists now
# live in discovery.py, which is the only module that calls AWS APIs. They
# are imported above so the permission-gap inference below keeps working
# unchanged.

SERVICE_ALIASES = {
    "api gateway": "apigateway",
    "amazon api gateway": "apigateway",
    "aws lambda": "lambda",
    "amazon dynamodb": "dynamodb",
    "amazon ec2": "ec2",
    "ec2 instance": "ec2",
    "amazon ecs": "ecs",
    "amazon eks": "eks",
    "amazon aurora": "aurora",
    "aurora": "aurora",
    "amazon rds": "rds",
    "mysql": "mysql",
    "mysql database": "mysql",
    "mariadb": "mariadb",
    "mariadb database": "mariadb",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "mongodb database": "mongodb",
    "oracle": "oracle",
    "oracle database": "oracle",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "postgresql database": "postgresql",
    "mssql": "sqlserver",
    "microsoft sql server": "sqlserver",
    "sql server": "sqlserver",
    "sqlserver": "sqlserver",
    "ms sql": "sqlserver",
    "db2": "db2",
    "ibm db2": "db2",
    "sap hana": "hana",
    "amazon s3": "s3",
    "aws kms": "kms",
    "amazon kms": "kms",
    "amazon elasticache": "elasticache",
    "redis": "elasticache",
    "amazon opensearch service": "opensearch",
    "opensearch service": "opensearch",
    "amazon sqs": "sqs",
    "amazon sns": "sns",
    "amazon eventbridge": "eventbridge",
    "amazon kinesis": "kinesis",
    "amazon redshift": "redshift",
    "amazon bedrock": "bedrock",
    "amazon sagemaker": "sagemaker",
    "aws cloudtrail": "cloudtrail",
    "amazon cloudwatch": "cloudwatch",
    "cloudwatch logs": "logs",
    "aws organizations": "organizations",
    "aws control tower": "controltower",
    "amazon cognito": "cognito",
    "aws iam": "iam",
    "aws secrets manager": "secretsmanager",
    "application load balancer": "alb",
    "elastic load balancing": "elb",
    "amazon route 53": "route53",
}

DATABASE_ENGINE_SERVICES = {
    "mysql",
    "postgresql",
    "mariadb",
    "mongodb",
    "oracle",
    "sqlserver",
    "db2",
    "hana",
}
MESSAGING_SERVICES = {"sqs", "sns", "eventbridge", "kinesis"}
AI_ML_SERVICES = {"bedrock", "sagemaker", "comprehend", "rekognition", "transcribe", "translate", "kendra"}


class AssessmentError(Exception):
    """Base error that the CLI and MCP wrapper can return without tracebacks."""

    code = "assessment_error"
    exit_code = 1

    def __init__(self, message: str, *, detail: str | None = None, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail
        if exit_code is not None:
            self.exit_code = exit_code

    def to_dict(self) -> dict[str, Any]:
        error = {"code": self.code, "message": self.message}
        if self.detail:
            error["detail"] = self.detail
        return {"error": error}


class InputFileError(AssessmentError):
    code = "input_file_error"


class OutputFileError(AssessmentError):
    code = "output_file_error"


class SessionStoreError(AssessmentError):
    code = "session_store_error"


class ValidationError(AssessmentError):
    code = "validation_error"


# One Evidence record backs exactly one control. `status` and `confidence`
# are kept as separate fields (not folded into one "score") because the
# rubric treats them as independent axes: a control can be confidently
# "missing" or unconfidently "met", and reports need to show both.
@dataclass(frozen=True)
class Evidence:
    control_id: str
    status: str = "unknown"
    confidence: str = "low"
    evidence_state: str = "unknown"
    summary: str = "No evidence supplied."
    source: str = "unknown"
    timestamp: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], redactor: "Redactor") -> "Evidence":
        sanitized = redactor.sanitize(value)
        if not isinstance(sanitized, Mapping):
            sanitized = {}
        return cls(
            control_id=str(sanitized.get("control_id", "")).strip(),
            status=normalize_status(sanitized.get("status")),
            confidence=normalize_confidence(sanitized.get("confidence")),
            evidence_state=normalize_evidence_state(sanitized.get("evidence_state")),
            summary=str(sanitized.get("summary", "No evidence supplied.")),
            source=str(sanitized.get("source", "unknown")),
            timestamp=_optional_string(sanitized.get("timestamp")),
            metadata=dict(sanitized.get("metadata", {}))
            if isinstance(sanitized.get("metadata"), Mapping)
            else {},
        )


# What was assessed and how much access the assessor had. `access_mode`
# drives which AWS permissions discovery.py will request, and `scope_type`
# feeds the "single-account confidence is limited" disclaimer further down.
@dataclass(frozen=True)
class Scope:
    assessment_id: str = "local-assessment"
    scope_type: str = "single-account"
    access_mode: str = "minimum_read_only"
    regions: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


# Everything about the customer's business that can't be inferred from an
# AWS API call. `answers` holds the raw fixed-question responses (see
# rubric.QUESTIONS); the named fields above it are the subset of those
# answers the scoring logic reads most often, kept as first-class fields so
# callers can set them directly instead of always going through `answers`.
@dataclass(frozen=True)
class BusinessContext:
    stage: str = "unknown"
    target_segment: str = "unknown"
    pricing_model: str = "unknown"
    tenancy_model: str = "unknown"
    growth_pressure: str = "unknown"
    answers: tuple[dict[str, Any], ...] = ()


# One rubric control after scoring. `score` is None for `unknown` and
# `not_applicable` (see STATUS_SCORES) rather than 0.0, so downstream
# averaging can tell "excluded from the average" apart from "scored zero".
@dataclass(frozen=True)
class ControlResult:
    id: str
    title: str
    status: str
    score: float | None
    confidence: str
    evidence_state: str
    evidence_summary: str
    evidence_source: str
    why: str
    recommendation: str
    sources: tuple[str, ...]


# One rubric dimension (e.g. Tenant Architecture and Isolation) after
# scoring all of its controls. `unknown_control_count` /
# `applicable_control_count` are carried here (not recomputed later) because
# apply_maturity_gates() needs the unknown ratio per dimension to decide
# whether weak evidence should cap the overall score.
@dataclass(frozen=True)
class DimensionResult:
    id: str
    name: str
    score: float | None
    confidence: str
    weight: float
    why: str
    customer_question: str
    unknown_control_count: int
    applicable_control_count: int
    controls: tuple[ControlResult, ...]


# One "top action" surfaced in the report. `service_notes` is populated by
# stack_context_notes() and folded into `action`'s text, but kept as a
# separate field too so the HTML/Markdown renderers can show it as its own
# bullet list instead of one long paragraph.
@dataclass(frozen=True)
class RecommendationResult:
    control_id: str
    title: str
    priority: str
    action: str
    status: str
    confidence: str
    sources: tuple[str, ...]
    service_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageResult:
    """Report-level evidence breadth without changing maturity calculations."""

    report_status: str
    assessed_controls: int
    total_controls: int
    scoreable_controls: int
    unknown_controls: int
    not_applicable_controls: int
    coverage_ratio: float
    evidence_source_counts: dict[str, int]


# The full result of one assessment run. This is the single object every
# output writer (HTML, JSON, findings, summary Markdown) renders from, so
# adding a new output format should never require re-running the scoring
# pipeline - it only ever needs a new renderer over this shape.
@dataclass(frozen=True)
class AssessmentResult:
    generated_at: str
    assessment_id: str
    scope: Scope
    business_context: BusinessContext
    overall_score: float | None
    overall_confidence: str
    coverage: CoverageResult
    maturity_scale: dict[int, str]
    dimensions: tuple[DimensionResult, ...]
    input_observations: tuple[str, ...]
    service_observations: tuple[str, ...]
    top_recommendations: tuple[RecommendationResult, ...]
    routing_recommendations: tuple[str, ...]
    advisory_overlays: tuple[str, ...]
    evidence_gaps: tuple[str, ...]
    source_catalog: dict[str, dict[str, str]]
    disclaimers: tuple[str, ...]


class Redactor:
    """Redacts common sensitive values before evidence reaches reports."""

    _patterns: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\b\d{12}\b"), "[redacted-account-id]"),
        (re.compile(r"arn:aws[a-zA-Z-]*:[^\s,;\"']+"), "[redacted-arn]"),
        (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[redacted-email]"),
        (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[redacted-access-key-id]"),
        (
            re.compile(r"(?i)\b(password|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*[^\s,;]+"),
            r"\1=[redacted-sensitive-value]",
        ),
    )

    def __init__(self, sensitive_terms: tuple[str, ...] = ()) -> None:
        self._sensitive_terms = tuple(term for term in sensitive_terms if term)

    def sanitize_text(self, value: str) -> str:
        sanitized = value
        for pattern, replacement in self._patterns:
            sanitized = pattern.sub(replacement, sanitized)
        for term in self._sensitive_terms:
            sanitized = sanitized.replace(term, "[redacted-sensitive-term]")
        return sanitized

    def sanitize(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.sanitize_text(value)
        if isinstance(value, Mapping):
            return {str(key): self.sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.sanitize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.sanitize(item) for item in value)
        return value


class JsonSessionStore(SessionStore):
    """Local JSON implementation for repeatable business-question answers."""

    def __init__(self, path: Path, redactor: Redactor | None = None) -> None:
        self._path = path
        self._redactor = redactor or Redactor()
        # Guards the full read-modify-write cycle in set_answer()/
        # mark_derived_current() against concurrent tool calls in the same
        # process (e.g. a model issuing several save_assessment_answer
        # calls close together). Without this, two writers can each read
        # the same on-disk state, and the second write silently discards
        # the first writer's change (last write wins).
        self._lock = threading.Lock()

    def list_answers(self) -> tuple[SessionAnswer, ...]:
        state = self._read()
        answers = state.get("answers", {})
        if not isinstance(answers, Mapping):
            return ()
        normalized = []
        for question_id, item in sorted(answers.items()):
            if not isinstance(item, Mapping):
                continue
            normalized.append(
                SessionAnswer(
                    question_id=str(question_id),
                    answer_value=str(item.get("answer_value", "")),
                    source=str(item.get("source", "session")),
                    timestamp=str(item.get("timestamp", "")),
                    changed=bool(item.get("changed", False)),
                )
            )
        return tuple(normalized)

    def set_answer(self, question_id: str, answer_value: str, source: str = "cli") -> SessionAnswer:
        if not question_id.strip():
            raise SessionStoreError("Question ID cannot be empty.")

        # Hold the lock across the full read-modify-write cycle, not just
        # the write, so a second call in another thread can't read stale
        # state while this one is still in flight.
        with self._lock:
            state = self._read()
            answers = state.setdefault("answers", {})
            if not isinstance(answers, dict):
                answers = {}
                state["answers"] = answers

            sanitized_value = str(self._redactor.sanitize(answer_value)).strip()
            previous = answers.get(question_id)
            changed = bool(isinstance(previous, Mapping) and previous.get("answer_value") != sanitized_value)
            answer = SessionAnswer(
                question_id=question_id,
                answer_value=sanitized_value,
                source=source,
                timestamp=utc_now(),
                changed=changed,
            )
            answers[question_id] = asdict(answer)
            state["derived_state"] = {
                "stale": True,
                "reason": "business-question answer changed" if changed else "business-question answer set",
                "updated_at": answer.timestamp,
            }
            self._write(state)
        return answer

    def as_business_context_answers(self) -> tuple[dict[str, Any], ...]:
        return tuple(asdict(answer) for answer in self.list_answers())

    def mark_derived_current(self, assessment_id: str) -> None:
        with self._lock:
            state = self._read()
            state["derived_state"] = {
                "stale": False,
                "assessment_id": assessment_id,
                "updated_at": utc_now(),
            }
            self._write(state)

    def _read(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"answers": {}, "derived_state": {"stale": True}}
        try:
            state = json.loads(self._path.read_text(encoding="utf-8"))
        except JSONDecodeError as exc:
            raise SessionStoreError(
                f"Session file {self._path} is not valid JSON.",
                detail=str(exc),
            ) from exc
        except OSError as exc:
            raise SessionStoreError(
                f"Could not read session file {self._path}.",
                detail=str(exc),
            ) from exc
        if not isinstance(state, dict):
            raise SessionStoreError(f"Session file {self._path} must contain a JSON object.")
        return state

    def _write(self, state: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # A unique temp filename per write (pid + random suffix) avoids
            # collisions if a write ever happens outside the in-process
            # lock above (e.g. a second OS process using the same session
            # file), rather than every writer racing to replace() the same
            # fixed "<name>.tmp" path.
            tmp_path = self._path.with_suffix(
                f"{self._path.suffix}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
            )
            tmp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp_path.replace(self._path)
        except OSError as exc:
            raise SessionStoreError(
                f"Could not write session file {self._path}.",
                detail=str(exc),
            ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AssessmentError as exc:
        print(json.dumps(exc.to_dict(), sort_keys=True), file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - last-resort CLI guardrail
        error = AssessmentError(
            "Unexpected failure while running the assessment.",
            detail=str(exc),
        )
        print(json.dumps(error.to_dict(), sort_keys=True), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="saas-readiness")
    subcommands = parser.add_subparsers(dest="command", required=True)

    assess = subcommands.add_parser("assess", help="Run the assessment and write the HTML report plus optional artifacts.")
    assess.add_argument("--input", help="Input JSON file. If omitted, all controls start unknown.")
    assess.add_argument("--output", default=DEFAULT_OUTPUT_PATH, help="HTML report path.")
    assess.add_argument("--json-debug", help="Optional machine-readable debug output path (legacy name for --assessment-json).")
    assess.add_argument("--assessment-json", help="Optional path to write the canonical assessment.json artifact.")
    assess.add_argument("--findings-json", help="Optional path to write the normalized findings.json artifact.")
    assess.add_argument("--summary-md", help="Optional path to write the customer-facing summary.md artifact.")
    assess.add_argument("--session", default=DEFAULT_SESSION_PATH, help="Session answer file path.")
    assess.add_argument("--no-session", action="store_true", help="Do not merge saved session answers.")
    assess.add_argument(
        "--discover-aws",
        action="store_true",
        help="Run read-only AWS discovery (Stage 1 classification plus Stage 2 conditional service checks).",
    )
    assess.add_argument(
        "--explain",
        choices=["none", "bedrock"],
        default="none",
        help="Optional LLM narrative layer. 'none' (default) runs fully deterministic with no model call.",
    )
    assess.add_argument(
        "--explain-model-id",
        default=None,
        help="Model ID for --explain bedrock. Defaults to BEDROCK_MODEL_ID.",
    )
    assess.add_argument(
        "--explain-region",
        default=None,
        help="AWS region for --explain bedrock. Defaults to BEDROCK_REGION.",
    )
    assess.set_defaults(func=cmd_assess)

    questions = subcommands.add_parser("questions", help="List fixed follow-up questions.")
    questions.add_argument("--input", help="Optional assessment input JSON for context.")
    questions.add_argument("--session", default=DEFAULT_SESSION_PATH, help="Session answer file path.")
    questions.add_argument("--limit", type=int, default=5)
    questions.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    questions.set_defaults(func=cmd_questions)

    answer_set = subcommands.add_parser("answer-set", help="Store or update one fixed question answer.")
    answer_set.add_argument("--session", default=DEFAULT_SESSION_PATH, help="Session answer file path.")
    answer_set.add_argument("--question-id", required=True)
    answer_set.add_argument("--value", required=True)
    answer_set.add_argument("--source", default="cli")
    answer_set.set_defaults(func=cmd_answer_set)

    answers = subcommands.add_parser("answers", help="Show saved question answers.")
    answers.add_argument("--session", default=DEFAULT_SESSION_PATH, help="Session answer file path.")
    answers.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    answers.set_defaults(func=cmd_answers)

    for command in (assess, questions, answer_set, answers):
        command.add_argument(
            "--session-profile",
            choices=["v1", "v2"],
            default=None,
            help="Persistence profile. Defaults to SESSION_PROFILE or v1.",
        )

    return parser


def _session_store_for_args(
    base_dir: Path, args: argparse.Namespace, redactor: Redactor
) -> SessionStore:
    """Construct the selected profile while preserving v1 path validation."""

    try:
        from src.config import load_settings
        from src.session_profiles import build_session_store
    except ModuleNotFoundError:  # pragma: no cover - direct src execution
        from config import load_settings  # type: ignore[import-not-found, no-redef]
        from session_profiles import build_session_store  # type: ignore[import-not-found, no-redef]

    requested_path = str(getattr(args, "session", DEFAULT_SESSION_PATH))
    path_override = None if requested_path == DEFAULT_SESSION_PATH else requested_path
    settings = load_settings(
        profile_override=getattr(args, "session_profile", None),
        session_path_override=path_override,
    )
    local_path = (
        safe_path(base_dir, settings.session_path, "session")
        if settings.session_profile == "v1"
        else None
    )
    return build_session_store(settings, redactor, local_path=local_path)


def cmd_assess(args: argparse.Namespace) -> int:
    base_dir = Path.cwd()
    redactor = Redactor()
    payload = load_payload(base_dir, args.input) if args.input else {}

    session_store: SessionStore | None = None
    if not args.no_session:
        session_store = _session_store_for_args(base_dir, args, redactor)
        payload = merge_session_answers(payload, session_store)

    if args.discover_aws:
        payload = merge_aws_preflight(payload)

    result = assess_payload(payload, redactor=redactor)
    output_path = safe_path(base_dir, args.output, "HTML report")
    write_html_report(output_path, result, redactor)
    written = [display_path(output_path, base_dir)]

    # --explain only ever adds narrative text on top of the already-final
    # deterministic result. It cannot be requested before assess_payload()
    # returns, by construction, so there is no code path where a model call
    # could influence result.overall_score or any control status.
    explanation: ExplanationBundle | None = None
    if args.explain != "none":
        explainer = build_explainer(args.explain, model_id=args.explain_model_id, region=args.explain_region)
        sanitized_result = redactor.sanitize(to_plain(result))
        explanation = explainer.explain(sanitized_result)
        if not explanation.executive_summary:
            # Keep the graceful fallback (the deterministic report is still
            # written), but never let a requested narrative vanish silently.
            reason = explanation.failure_reason or explanation.generated_by
            if explanation.generated_by == "none":
                reason = "boto3 is not installed"
            print(
                f"Warning: --explain {args.explain} produced no narrative ({reason}); "
                "summary.md is written without it. Check Amazon Bedrock model access, "
                "credentials, BEDROCK_MODEL_ID and BEDROCK_REGION.",
                file=sys.stderr,
            )

    debug_json_path = args.json_debug or args.assessment_json
    if debug_json_path:
        resolved = safe_path(base_dir, debug_json_path, "assessment JSON")
        write_assessment_json(resolved, result, redactor)
        written.append(display_path(resolved, base_dir))

    if args.findings_json:
        resolved = safe_path(base_dir, args.findings_json, "findings JSON")
        write_findings_json(resolved, result, redactor)
        written.append(display_path(resolved, base_dir))

    if args.summary_md:
        resolved = safe_path(base_dir, args.summary_md, "summary Markdown")
        write_summary_markdown(resolved, result, explanation, redactor)
        written.append(display_path(resolved, base_dir))

    if session_store:
        session_store.mark_derived_current(result.assessment_id)

    print(f"Wrote HTML report: {written[0]}")
    for extra_path in written[1:]:
        print(f"Wrote additional artifact: {extra_path}")
    return 0


def cmd_questions(args: argparse.Namespace) -> int:
    base_dir = Path.cwd()
    payload = load_payload(base_dir, args.input) if args.input else {}
    redactor = Redactor()
    store = _session_store_for_args(base_dir, args, redactor)
    payload = merge_session_answers(payload, store)

    result = assess_payload(payload, redactor=redactor)
    answered = answered_question_ids(payload)
    selected = select_questions(result, answered, max(args.limit, 0))

    if args.json:
        print(json.dumps(selected, indent=2, sort_keys=True))
        return 0

    if not selected:
        print("No unanswered fixed questions were selected from the current evidence.")
        return 0

    print(
        "Each topic below may cover more than one signal. Answer each signal\n"
        "separately with its own 'answer-set' command, using one of the listed\n"
        "option values for --value:\n"
        "  saas-readiness-assess answer-set --question-id <BQ-ID> --value <option> --source cli\n"
    )
    for question in selected:
        print(f"{question['id']}: {question['prompt']}")
        for signal_id, signal in question.get("scoring_ids", {}).items():
            if not isinstance(signal, Mapping):
                continue
            label = signal.get("label", "")
            options = ", ".join(str(option) for option in signal.get("options", ()))
            label_suffix = f" ({label})" if label else ""
            print(f"  {signal_id}{label_suffix} — options: {options}")
            print(
                f"    saas-readiness-assess answer-set --question-id {signal_id} "
                f"--value <option> --source cli"
            )
        print()
    return 0


def cmd_answer_set(args: argparse.Namespace) -> int:
    base_dir = Path.cwd()
    store = _session_store_for_args(base_dir, args, Redactor())
    answer = store.set_answer(args.question_id, args.value, args.source)
    state = "changed" if answer.changed else "current"
    print(f"{answer.question_id}: {answer.answer_value} ({answer.source}, {state})")
    return 0


def cmd_answers(args: argparse.Namespace) -> int:
    base_dir = Path.cwd()
    store = _session_store_for_args(base_dir, args, Redactor())
    answers = store.list_answers()

    if args.json:
        print(json.dumps([asdict(answer) for answer in answers], indent=2, sort_keys=True))
        return 0

    if not answers:
        print("No saved answers.")
        return 0

    for answer in answers:
        state = "changed" if answer.changed else "current"
        print(f"{answer.question_id}: {answer.answer_value} ({answer.source}, {state})")
    return 0


def assess_payload(payload: Mapping[str, Any] | None, redactor: Redactor | None = None) -> AssessmentResult:
    """Run deterministic inference, scoring, routing, and report-data assembly."""

    if payload is None:
        payload = {}
    if not isinstance(payload, Mapping):
        raise ValidationError("Assessment input must be a JSON object.")

    redactor = redactor or Redactor()
    scope = parse_scope(mapping(payload.get("scope")))
    business_context = parse_business_context(mapping(payload.get("business_context")))
    facts = mapping(payload.get("facts"))

    evidence_by_control = infer_evidence(payload, scope, business_context, facts, redactor)
    dimensions = tuple(score_dimension(dimension, evidence_by_control) for dimension in DIMENSIONS)
    base_score = overall_score(dimensions)
    gated_score = apply_maturity_gates(base_score, dimensions)
    recommendations = rank_recommendations(dimensions, business_context, facts)
    coverage = build_coverage(dimensions)

    return AssessmentResult(
        generated_at=utc_now(),
        assessment_id=scope.assessment_id,
        scope=scope,
        business_context=business_context,
        overall_score=gated_score,
        overall_confidence=overall_confidence(dimensions),
        coverage=coverage,
        maturity_scale=dict(MATURITY_SCALE),
        dimensions=dimensions,
        input_observations=input_observations(scope, facts),
        service_observations=service_observations(facts),
        top_recommendations=recommendations,
        routing_recommendations=routing_recommendations(dimensions, business_context, facts),
        advisory_overlays=advisory_overlays(facts),
        evidence_gaps=evidence_gaps(dimensions),
        source_catalog=dict(SOURCES),
        disclaimers=(
            "Level 0 assessment only: observe and report, with no customer-resource mutation.",
            "Scores reflect available evidence; missing permissions and unanswered questions lower confidence.",
            "Deterministic code owns statuses, scores, confidence, and report data.",
            scope_disclaimer(scope),
            "Reports are sanitized for common sensitive values, but review before external sharing.",
        ),
    )


def infer_evidence(
    payload: Mapping[str, Any],
    scope: Scope,
    business_context: BusinessContext,
    facts: Mapping[str, Any],
    redactor: Redactor,
) -> dict[str, Evidence]:
    """Normalize explicit, customer, permission, and fact evidence by control ID."""

    evidence_by_control = explicit_evidence(payload.get("evidence"), redactor)
    answers = answer_map(business_context.answers)

    # Prefer observed technical signals over customer assertions. Explicit
    # reviewed evidence is seeded first and remains highest precedence.
    add_ec2_database_evidence(evidence_by_control, facts)
    add_signal_evidence(evidence_by_control, facts)
    add_business_context_evidence(evidence_by_control, business_context, answers)
    add_applicability_evidence(evidence_by_control, scope, business_context, answers, facts)
    add_permission_gap_evidence(evidence_by_control, facts)

    return evidence_by_control


def explicit_evidence(value: Any, redactor: Redactor) -> dict[str, Evidence]:
    """Seed evidence from the caller-supplied `evidence` list.

    This runs first in infer_evidence()'s pipeline and populates the dict
    that every later inference step then calls set_if_absent() against - so
    anything explicitly supplied here always wins over anything inferred
    later, matching the rubric's "explicit evidence wins over inferred
    evidence" rule.
    """

    evidence_by_control: dict[str, Evidence] = {}
    if not isinstance(value, list):
        return evidence_by_control

    for item in value:
        if not isinstance(item, Mapping):
            continue
        evidence = Evidence.from_mapping(item, redactor)
        if evidence.control_id:
            evidence_by_control[evidence.control_id] = evidence
    return evidence_by_control


def add_business_context_evidence(
    evidence_by_control: dict[str, Evidence],
    business_context: BusinessContext,
    answers: dict[str, str],
) -> None:
    """Translate canonical customer signals into conservative evidence."""

    context_values = (
        business_context.stage,
        business_context.target_segment,
        business_context.growth_pressure,
    )
    known_context = [value for value in context_values if value and value != "unknown"]
    if known_context:
        complete = len(known_context) == len(context_values)
        set_if_absent(
            evidence_by_control,
            Evidence(
                control_id="SBR-01",
                status="met" if complete else "partial",
                confidence="high" if complete else "medium",
                evidence_state="customer_asserted",
                summary=(
                    "Business stage, target segment, and growth pressure are available."
                    if complete
                    else "Business context is partially known; additional context is needed."
                ),
                source="business-context",
            ),
        )

    add_direct_answer_evidence(evidence_by_control, answers)


def add_direct_answer_evidence(
    evidence_by_control: dict[str, Evidence], answers: dict[str, str]
) -> None:
    """Apply exact catalog mappings; unrecognized prose remains unscored."""

    for question_id, option_rules in ANSWER_CONTROL_RULES.items():
        answer = answers.get(question_id, "").strip().lower()
        controls = option_rules.get(answer)
        if not controls:
            continue
        for control_id, status in controls:
            set_if_absent(
                evidence_by_control,
                Evidence(
                    control_id=control_id,
                    status=status,
                    confidence="medium",
                    evidence_state="customer_asserted",
                    summary=f"Customer/session answer {question_id}: {answer}",
                    source="business-question",
                ),
            )


def add_applicability_evidence(
    evidence_by_control: dict[str, Evidence],
    scope: Scope,
    business_context: BusinessContext,
    answers: dict[str, str],
    facts: Mapping[str, Any],
) -> None:
    shared_resources = bool_fact(facts, "shared_resources")
    compliance_answer = answers.get("BQ-010", "").lower()
    metering_requirement = answers.get("BQ-023", "").lower()
    pricing_model = business_context.pricing_model.lower()
    stage = business_context.stage.lower()

    if shared_resources is False:
        for control_id in ("TAI-03", "TAI-04", "OOR-03", "CAM-06"):
            set_if_absent(
                evidence_by_control,
                Evidence(
                    control_id=control_id,
                    status="not_applicable",
                    confidence="medium",
                    evidence_state="confirmed",
                    summary="Supplied facts indicate there are no material shared tenant resources in scope.",
                    source="applicability",
                ),
            )

    if compliance_answer == "none_known":
        for control_id in ("TAI-05", "TAI-06"):
            set_if_absent(
                evidence_by_control,
                Evidence(
                    control_id=control_id,
                    status="not_applicable",
                    confidence="medium",
                    evidence_state="confirmed",
                    summary=(
                        "Customer/session says premium isolation, compliance, or residency "
                        "requirements are not expected soon."
                    ),
                    source="business-question",
                ),
            )

    if metering_requirement == "not_required" and pricing_model not in {
        "usage_based",
        "hybrid",
    }:
        set_if_absent(
            evidence_by_control,
            Evidence(
                control_id="CAM-02",
                status="not_applicable",
                confidence="medium",
                evidence_state="confirmed",
                summary="Customer/session says pricing does not require usage metering today or soon.",
                source="business-question",
            ),
        )

    if stage == "pre_launch":
        for control_id in ("OOR-02", "SBR-03", "SBR-04"):
            set_if_absent(
                evidence_by_control,
                Evidence(
                    control_id=control_id,
                    status="not_applicable",
                    confidence="medium",
                    evidence_state="confirmed",
                    summary="Pre-customer/prototype stage makes this control non-applicable for now.",
                    source="business-context",
                ),
            )

    if scope.scope_type == "single-account":
        set_if_absent(
            evidence_by_control,
            Evidence(
                control_id="DPA-04",
                status="unknown",
                confidence="low",
                evidence_state="unknown",
                summary=(
                    "Single-account scope limits confidence for environment, account, and region "
                    "promotion; org-level evidence was not supplied."
                ),
                source="scope-limit",
            ),
        )


def add_permission_gap_evidence(evidence_by_control: dict[str, Evidence], facts: Mapping[str, Any]) -> None:
    # Missing permissions are evidence gaps, not proof that a capability is absent.
    for permission in string_list(fact(facts, "missing_permissions")):
        controls = PERMISSION_CONTROL_MAP.get(permission, ("TAI-01",))
        for control_id in controls:
            set_if_absent(
                evidence_by_control,
                Evidence(
                    control_id=control_id,
                    status="unknown",
                    confidence="low",
                    evidence_state="unknown",
                    summary=f"Not assessed because read-only permission {permission} was unavailable.",
                    source="permission-preflight",
                    metadata={"missing_permission": permission},
                ),
            )


def add_ec2_database_evidence(evidence_by_control: dict[str, Evidence], facts: Mapping[str, Any]) -> None:
    signal_value = signal(facts, "self_managed_database_on_ec2")
    services = set(service_names(facts))
    has_ec2_database_service = "ec2" in services and bool(services.intersection(DATABASE_ENGINE_SERVICES))
    if not signal_value.get("inspected") and not has_ec2_database_service:
        return

    detected = bool(signal_value.get("detected", has_ec2_database_service))
    if not detected:
        return

    engine = str(signal_value.get("engine", "self-managed database")).strip() or "self-managed database"
    tenant_isolation = signal_value.get("tenant_isolation_detected")
    tenant_metrics = signal_value.get("tenant_metrics_detected")
    tenant_consumption = signal_value.get("tenant_consumption_detected")

    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id="TAI-03",
            status=signal_status(tenant_isolation),
            confidence="medium" if tenant_isolation is not None else "low",
            evidence_state="suggestive",
            summary=(
                f"{engine} appears to run on EC2. Verify database/schema/table/row-level "
                "tenant isolation, host and security-group boundaries, patching, backups, "
                "encryption, and privileged access paths."
            ),
            source="fact-signal:self_managed_database_on_ec2",
        ),
    )
    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id="OOR-01",
            status=signal_status(tenant_metrics),
            confidence="medium" if tenant_metrics is not None else "low",
            evidence_state="suggestive",
            summary=(
                f"{engine} on EC2 needs tenant-aware database and host telemetry; managed "
                "RDS/Aurora metrics will not cover this data layer."
            ),
            source="fact-signal:self_managed_database_on_ec2",
        ),
    )
    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id="CAM-06",
            status=signal_status(tenant_consumption),
            confidence="medium" if tenant_consumption is not None else "low",
            evidence_state="suggestive",
            summary=(
                f"{engine} on EC2 needs tenant consumption or proxy metrics for EC2/EBS "
                "cost attribution unless each tenant has dedicated instances or volumes."
            ),
            source="fact-signal:self_managed_database_on_ec2",
        ),
    )


def add_signal_evidence(evidence_by_control: dict[str, Evidence], facts: Mapping[str, Any]) -> None:
    signal_rules = (
        ("iac", "DPA-01", "IaC or repeatable environment automation signals were detected.", "Environment automation inspection completed, but no IaC or repeatable setup signal was detected."),
        ("tenant_registry", "TLO-01", "A possible tenant registry or tenant metadata source was detected.", "Tenant registry inspection completed, but no tenant metadata source was detected."),
        ("edge_multi_tenancy", "ITC-01", "Per-tenant edge signals (CloudFront distributions/SaaS Manager tenants, per-tenant TLS certs, or edge WAF) were detected, suggesting tenant context is established at the edge.", "Edge inspection completed, but no per-tenant edge routing, custom-domain/TLS, or edge-protection signal was detected."),
        ("agent_memory_isolation", "TAI-03", "Per-tenant vector indexes (e.g. S3 Vectors indexes carrying a tenant identifier) were detected, suggesting tenant-isolated agent memory (silo model).", "Vector-store inspection completed, but no per-tenant vector index was detected."),
        ("tenant_telemetry", "OOR-01", "Tenant-aware telemetry dimensions were detected.", "Telemetry inspection completed, but no tenant-aware log, metric, or trace dimensions were detected."),
        ("tenant_telemetry", "ITC-04", "Tenant context appears in telemetry or audit records.", "Telemetry inspection completed, but tenant context was not found in telemetry or audit records."),
        ("deployment_pipeline", "DPA-02", "A controlled deployment pipeline or release workflow was detected.", "Deployment inspection completed, but no controlled release pipeline was detected."),
        ("billing_metering", "CAM-02", "Tenant-scoped metering or usage events were detected.", "Metering inspection completed, but no billing-ready tenant usage events were detected."),
        ("tenant_context_propagation", "ITC-02", "Tenant context propagation signals were detected.", "Tenant context propagation was inspected, but no consistent propagation signal was detected."),
        ("tenant_authorization", "ITC-03", "Authorization or data-access paths appear to consume tenant context.", "Authorization/data-access inspection completed, but tenant-context enforcement was not detected."),
        ("tenant_scoped_admin", "ITC-05", "Admin or support access appears tenant-scoped.", "Admin/support access inspection completed, but tenant scoping was not detected."),
        ("control_plane", "TLO-02", "Control-plane onboarding or lifecycle workflow signals were detected.", "Lifecycle inspection completed, but no repeatable control-plane workflow was detected."),
        ("offboarding", "TLO-04", "Tenant offboarding or retention workflow signals were detected.", "Offboarding inspection completed, but no defined tenant offboarding workflow was detected."),
        ("release_safety", "DPA-05", "Release safety signals such as canary, rollback, or validation were detected.", "Release safety inspection completed, but rollback/staged rollout/tenant validation was not detected."),
        ("same_version", "DPA-03", "Same-version or version-governance signals were detected.", "Version inspection completed, but no same-version discipline or drift control was detected."),
        ("business_metrics", "SBR-03", "Activation, onboarding, adoption, or product-success metrics were detected.", "Business metric inspection completed, but activation/onboarding/adoption measures were not detected."),
        ("customer_feedback", "SBR-04", "Retention, expansion, or customer feedback loops were detected.", "Feedback-loop inspection completed, but retention, expansion, or customer feedback signals were not detected."),
    )

    for signal_name, control_id, detected_summary, missing_summary in signal_rules:
        signal_to_control(evidence_by_control, facts, signal_name, control_id, detected_summary, missing_summary)

    cost_allocation_tag_evidence(evidence_by_control, facts)
    alarm_signal(evidence_by_control, facts)


def cost_allocation_tag_evidence(
    evidence_by_control: dict[str, Evidence], facts: Mapping[str, Any]
) -> None:
    """Use tag inspection as suggestive evidence, never as coverage proof."""

    item = signal(facts, "cost_allocation_tags")
    if not item.get("inspected"):
        return
    matched = [str(key) for key in item.get("matched_tag_keys", [])]
    sample_count = int(item.get("tagged_resource_sample_count", 0))
    if matched:
        summary = (
            "Observed tag keys suggestive of cost or tenant grouping in a bounded tagged-resource "
            f"sample: {', '.join(matched[:5])}. Tag presence alone does not prove coverage."
        )
        status = "partial"
        confidence = "medium"
        state = "suggestive"
    else:
        summary = (
            "No cost or tenant grouping tag key was observed in the tag-key inventory and "
            f"sample of {sample_count} tagged resources. Untagged resources and tag coverage "
            "were not fully assessed, so cost allocation remains unverified."
        )
        status = "unknown"
        confidence = "low"
        state = "unknown"
    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id="CAM-01",
            status=status,
            confidence=confidence,
            evidence_state=state,
            summary=summary,
            source="aws-discovery",
        ),
    )


def signal_to_control(
    evidence_by_control: dict[str, Evidence],
    facts: Mapping[str, Any],
    signal_name: str,
    control_id: str,
    detected_summary: str,
    missing_summary: str,
) -> None:
    """Turn one named fact-signal into evidence for one control.

    `inspected` and `detected` are independent flags on purpose: a signal
    that was never inspected (e.g. the permission to check it was missing)
    must stay `unknown` and is skipped here entirely, while an
    inspected-but-absent signal becomes a confirmed `missing` finding below.
    """

    item = signal(facts, signal_name)
    if not item.get("inspected"):
        return

    detected = bool(item.get("detected"))
    confirmed = bool(item.get("confirmed"))
    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id=control_id,
            status="met" if detected and confirmed else "partial" if detected else "missing",
            confidence="high" if confirmed else "medium",
            evidence_state="confirmed" if confirmed else "suggestive",
            summary=detected_summary if detected else missing_summary,
            source=f"fact-signal:{signal_name}",
        ),
    )


def alarm_signal(evidence_by_control: dict[str, Evidence], facts: Mapping[str, Any]) -> None:
    """OOR-02 gets a three-way outcome that the generic signal_to_control() can't express.

    Plain signal_to_control() only distinguishes detected/not-detected, but
    alarms have a meaningful middle state: generic alarms with no tenant/tier
    dimension exist (`partial`, fleet averages hide tenant pain) versus no
    meaningful alarms at all (`missing`). That's why this control gets its
    own function instead of being folded into the signal_rules list above.
    """

    item = signal(facts, "tenant_alarms")
    if not item.get("inspected"):
        return

    detected = bool(item.get("detected"))
    any_alarms = bool(item.get("any_alarms", detected))
    status = "met" if detected else "partial" if any_alarms else "missing"
    summary = (
        "Tenant or tier-aware alarms/SLOs were detected."
        if detected
        else "Generic alarms exist, but tenant or tier impact is not visible."
        if any_alarms
        else "Alarm inspection completed, but no meaningful production alarms were detected."
    )
    set_if_absent(
        evidence_by_control,
        Evidence(
            control_id="OOR-02",
            status=status,
            confidence="medium",
            evidence_state="suggestive",
            summary=summary,
            source="fact-signal:tenant_alarms",
        ),
    )


def score_dimension(dimension: Mapping[str, Any], evidence_by_control: dict[str, Evidence]) -> DimensionResult:
    control_results = tuple(score_control(control, evidence_by_control) for control in dimension["controls"])

    # `score` is the average of each control's 0.0-1.0 status score, scaled
    # to the 0-5 customer-facing scale. `unknown`/`not_applicable` controls
    # have score=None and are excluded from `scoreable` entirely, so a
    # dimension with e.g. 3 unknowns and 1 "met" scores as 5/5 (not 1.25/5)
    # - unknown evidence lowers confidence below, never the raw score.
    scoreable = [control.score for control in control_results if control.score is not None]
    score = round((sum(scoreable) / len(scoreable)) * 5, 2) if scoreable else None

    # `not_applicable` controls are dropped from the denominator here too,
    # so a dimension where half the controls don't apply to this customer's
    # model isn't penalized for "only" having evidence on the other half.
    applicable = [control for control in control_results if control.status != "not_applicable"]
    unknown_count = sum(1 for control in applicable if control.status == "unknown")

    return DimensionResult(
        id=str(dimension["id"]),
        name=str(dimension["name"]),
        score=score,
        confidence=dimension_confidence(applicable),
        weight=float(dimension["weight"]),
        why=str(dimension["why"]),
        customer_question=str(dimension["customer_question"]),
        unknown_control_count=unknown_count,
        applicable_control_count=len(applicable),
        controls=control_results,
    )


def score_control(control: Mapping[str, Any], evidence_by_control: dict[str, Evidence]) -> ControlResult:
    evidence = evidence_by_control.get(str(control["id"]))
    if evidence is None:
        evidence = Evidence(control_id=str(control["id"]))

    status = normalize_status(evidence.status)
    return ControlResult(
        id=str(control["id"]),
        title=str(control["title"]),
        status=status,
        score=STATUS_SCORES[status],
        confidence=normalize_confidence(evidence.confidence),
        evidence_state=normalize_evidence_state(evidence.evidence_state),
        evidence_summary=evidence.summary,
        evidence_source=evidence.source,
        why=str(control["why"]),
        recommendation=str(control["recommendation"]),
        sources=tuple(str(source) for source in control.get("sources", ())),
    )


def dimension_confidence(controls: list[ControlResult]) -> str:
    """Roll individual control confidence up to one dimension-level rating.

    This is where "unknown evidence lowers confidence, not score" (the
    rubric's core rule) is actually enforced: score_dimension() above never
    penalizes the score for unknowns, so unknown_ratio here is the only
    place that effect shows up. More than half the controls unknown caps
    confidence at "low" outright, regardless of how strong the other
    evidence is.
    """

    if not controls:
        return "low"

    unknown_ratio = sum(1 for control in controls if control.status == "unknown") / len(controls)
    if unknown_ratio > 0.5:
        return "low"

    # Weighted average of per-control confidence (high=1.0/medium=0.6/low=0.3
    # from CONFIDENCE_WEIGHTS), with the unknown_ratio threshold tightening
    # as the average confidence claim gets stronger - a "high" confidence
    # rollup requires both a strong average AND few unknowns.
    average = sum(CONFIDENCE_WEIGHTS[control.confidence] for control in controls) / len(controls)
    if average >= 0.75 and unknown_ratio <= 0.25:
        return "high"
    if average >= 0.5 and unknown_ratio <= 0.5:
        return "medium"
    return "low"


def overall_score(dimensions: tuple[DimensionResult, ...]) -> float | None:
    """Weighted average of dimension scores, before maturity gates are applied.

    Renormalizes over only the dimensions that produced a score
    (`total_weight`) rather than dividing by the full rubric weight of 1.0.
    That matters when a whole dimension is unscoreable (every control
    unknown/not_applicable): without renormalizing, a strong result on the
    remaining dimensions would be diluted by a dimension that contributed no
    real signal, instead of just being left out of the average.
    """

    scoreable = [dimension for dimension in dimensions if dimension.score is not None]
    if not scoreable:
        return None
    total_weight = sum(dimension.weight for dimension in scoreable)
    if total_weight == 0:
        return None
    weighted = sum((dimension.score or 0.0) * dimension.weight for dimension in scoreable)
    return round(weighted / total_weight, 2)


def apply_maturity_gates(
    score: float | None,
    dimensions: tuple[DimensionResult, ...],
) -> float | None:
    if score is None:
        return None

    by_id = {dimension.id: dimension for dimension in dimensions}
    cap = 5.0

    # Gates keep a weighted average from hiding weak SaaS fundamentals: a
    # platform can't be "3/5 overall" if it has zero tenant isolation, even
    # if every other dimension is strong. Each gate below matches a rung in
    # the rubric's "Overall Maturity Gates" table - the thresholds and which
    # dimensions pair together are a rubric decision, not this code's.
    if score_at_or_below(by_id, ("TAI", "TLO"), 0.0):
        cap = min(cap, 1.0)
    if score_at_or_below(by_id, ("ITC", "DPA"), 1.0):
        cap = min(cap, 2.0)
    if score_at_or_below(by_id, ("CAM", "SBR"), 1.0):
        cap = min(cap, 3.0)

    # Separately from the per-dimension score gates above, if evidence is
    # broadly thin (most controls unknown in two or more dimensions), the
    # overall score is capped even if the few controls that WERE assessed
    # looked good - a strong result built on mostly-missing evidence isn't
    # trustworthy enough to report at face value.
    unknown_majority_dimensions = sum(
        1
        for dimension in dimensions
        if dimension.applicable_control_count
        and dimension.unknown_control_count / dimension.applicable_control_count > 0.5
    )
    if unknown_majority_dimensions >= 2:
        cap = min(cap, 2.0)
    return min(score, cap)


def rank_recommendations(
    dimensions: tuple[DimensionResult, ...],
    business_context: BusinessContext,
    facts: Mapping[str, Any],
) -> tuple[RecommendationResult, ...]:
    """Build the "Top Actions" list: every unresolved control, ranked, top 5 kept.

    "Unresolved" excludes `met` (nothing to recommend) and `not_applicable`
    (doesn't apply to this customer). Everything else - missing, partial,
    and unknown - is a candidate action, because even an unknown control is
    something the customer could resolve by answering a question or
    granting a permission.
    """

    candidates: list[tuple[int, RecommendationResult]] = []
    stage = business_context.stage

    for dimension in dimensions:
        for control in dimension.controls:
            if control.status in {"met", "not_applicable"}:
                continue
            service_notes = tuple(stack_context_notes(control.id, facts))
            action = " ".join((control.recommendation, *service_notes)).strip()
            priority = recommendation_priority(control, dimension.id, stage)
            candidates.append(
                (
                    priority_sort_value(priority, control.status),
                    RecommendationResult(
                        control_id=control.id,
                        title=control.title,
                        priority=priority,
                        action=action,
                        status=control.status,
                        confidence=control.confidence,
                        sources=control.sources,
                        service_notes=service_notes,
                    ),
                )
            )

    # Sort ascending by priority_sort_value: high-priority/missing-status
    # candidates get the lowest sort key, so they land first. Keeping only
    # the top 5 matches the design notes' "short ranked action list (3-5
    # items), not a flat recommendations dump" requirement.
    candidates.sort(key=lambda item: item[0])
    return tuple(candidate for _, candidate in candidates[:5])


def recommendation_priority(control: ControlResult, dimension_id: str, stage: str) -> str:
    """Decide high/medium/low priority for one control, adjusted by business stage.

    This implements the rubric's "Stage-Aware Severity Overlay": the same
    control result should not always carry the same urgency. A missing
    tenant-isolation control is always high priority regardless of stage,
    but a merely "medium" gap in, say, deployment automation becomes high
    priority specifically for a customer in the adoption stage, where
    scaling onboarding pain is the dominant risk.
    """

    foundational_dimensions = {"TAI", "ITC", "TLO", "DPA"}

    # Base priority from status/dimension alone, before stage is considered.
    if control.status == "missing":
        priority = "high"
    elif control.status == "partial":
        priority = "high" if dimension_id in {"TAI", "ITC"} else "medium"
    else:
        priority = "medium" if dimension_id in foundational_dimensions else "low"

    # Stage-specific escalation rules, one per stage from the rubric's
    # severity overlay table. Each only escalates (never downgrades) a
    # priority that the base logic above already assigned.
    if stage in {"launch", "scale"} and dimension_id in foundational_dimensions:
        return "high"
    if stage == "adoption" and dimension_id in {"TLO", "OOR", "DPA"} and priority == "medium":
        return "high"
    if stage == "optimization" and dimension_id in {"CAM", "OOR", "SBR"} and priority == "medium":
        return "high"
    return priority


def input_observations(scope: Scope, facts: Mapping[str, Any]) -> tuple[str, ...]:
    observations = [f"Assessment scope is {scope.scope_type} with {scope.access_mode} access mode."]
    services = service_names(facts)
    if services:
        observations.append(f"Detected or supplied service signals: {', '.join(sorted(set(services)))}.")

    missing_permissions = string_list(fact(facts, "missing_permissions"))
    if missing_permissions:
        observations.append(
            "Some areas were not assessed because these read-only permissions were missing: "
            f"{', '.join(missing_permissions)}."
        )

    if signal_detected(facts, "self_managed_database_on_ec2") or has_ec2_database_service(facts):
        observations.append(
            "A self-managed database on EC2 is in scope. Treat it as a data layer that needs "
            "explicit tenant isolation, telemetry, backup, patching, encryption, and cost "
            "attribution evidence."
        )

    # Live AWS discovery (src/discovery.py) attaches short human-readable
    # observations directly to facts when --discover-aws is used. These are
    # distinct from the service/permission observations above because they
    # describe what a live API call actually returned (e.g. VPC counts,
    # CloudFormation stack counts), not an inference from supplied facts.
    discovery_observations = string_list(fact(facts, "discovery_observations"))
    observations.extend(discovery_observations)
    return tuple(observations)


def service_observations(facts: Mapping[str, Any]) -> tuple[str, ...]:
    """One report bullet per detected service/stack, naming what to verify.

    Each `if` below is independent and additive - a customer running API
    Gateway + Lambda + DynamoDB AND S3 gets both observations, because the
    two stacks raise different verification questions. This is deliberately
    a flat list of service-specific rules rather than one generic
    "here are your services" message, per the rubric's requirement that
    recommendations speak to the customer's actual stack.
    """

    services = set(service_names(facts))
    observations: list[str] = []

    if {"apigateway", "lambda", "dynamodb"}.issubset(services):
        observations.append(
            "API Gateway, Lambda, and DynamoDB were detected. Validate tenant partition keys, "
            "authorizer tenant claims, Lambda concurrency/noisy-neighbor controls, API usage "
            "plans, and tenant-aware CloudWatch metrics."
        )
    if "eks" in services and services.intersection({"aurora", "rds"}):
        observations.append(
            "EKS with Aurora/RDS was detected. Validate namespace or pod isolation, "
            "service-account IAM roles, row-level security or schema separation, cluster "
            "observability, and tenant-aware database metrics."
        )
    if signal_detected(facts, "self_managed_database_on_ec2") or has_ec2_database_service(facts):
        observations.append(
            "Self-managed database on EC2 was detected. Validate database/schema/row-level "
            "tenant isolation, host and security-group boundaries, patching and backup "
            "ownership, encryption, tenant-aware DB metrics, and EC2/EBS cost attribution."
        )
    if "s3" in services:
        observations.append(
            "S3 is in scope. Validate bucket or prefix strategy, IAM conditions, KMS "
            "boundaries, lifecycle and retention rules, and storage/request attribution."
        )
    if "kms" in services:
        observations.append(
            "KMS is in scope. Validate keys, aliases, grants, and encryption context against "
            "the intended tenant or tier boundary."
        )
    if "elasticache" in services:
        observations.append(
            "ElastiCache or Redis-style caching is in scope. Validate key namespaces, memory "
            "and eviction isolation, hot-key detection, and tenant-aware cache metrics."
        )
    if "opensearch" in services:
        observations.append(
            "OpenSearch is in scope. Validate index or document separation, query filters, "
            "dashboard access boundaries, and tenant-level storage/query cost signals."
        )
    if services.intersection(MESSAGING_SERVICES):
        observations.append(
            "Messaging or event services are in scope. Validate tenant context in messages, "
            "consumer preservation of that context, tenant-impact-aware failures, and "
            "metering events where relevant."
        )
    if "ecs" in services:
        observations.append(
            "ECS is in scope. Validate task roles, service autoscaling, CPU/memory limits, "
            "deployment strategy, and tenant-aware service metrics."
        )
    if "redshift" in services:
        observations.append(
            "Redshift is in scope. Validate schema or row-level tenant controls, workload "
            "management, tenant-aware query/storage metrics, and shared analytics cost."
        )
    if "cognito" in services:
        observations.append(
            "Cognito is in scope. Validate authoritative tenant claims, app-client boundaries, "
            "identity federation, and tenant-aware authorization at the application edge."
        )
    if services.intersection({"iam", "secretsmanager", "cloudtrail", "controltower", "organizations"}):
        observations.append(
            "Governance and security services are in scope. Validate least privilege, secret "
            "boundaries, audit coverage, account strategy, and org-level visibility where available."
        )

    return tuple(observations)


def stack_context_notes(control_id: str, facts: Mapping[str, Any]) -> list[str]:
    """Per-control, per-stack guidance appended to a recommendation's action text.

    Similar shape to service_observations() above, but scoped to one control
    at a time via the `control_id in {...}` membership check, so a note only
    attaches to the specific controls it's actually relevant to (e.g. the
    DynamoDB partition-key note attaches to TAI-03/CAM-06, not to every
    control in the report).
    """

    services = set(service_names(facts))
    notes: list[str] = []

    if {"apigateway", "lambda", "dynamodb"}.issubset(services) and control_id in {
        "TAI-03",
        "TAI-04",
        "ITC-01",
        "OOR-01",
        "OOR-03",
        "CAM-02",
        "CAM-06",
    }:
        notes.append(
            "For the detected API Gateway, Lambda, and DynamoDB stack, validate tenant "
            "partition keys, authorizer claims, Lambda concurrency/noisy-neighbor controls, "
            "API usage plans, and tenant-aware CloudWatch metrics."
        )
    if (signal_detected(facts, "self_managed_database_on_ec2") or has_ec2_database_service(facts)) and control_id in {
        "TAI-02",
        "TAI-03",
        "OOR-01",
        "OOR-03",
        "CAM-03",
        "CAM-06",
        "DPA-01",
        "DPA-05",
    }:
        notes.append(
            "For a self-managed database on EC2, validate tenant separation in the database "
            "model, host and security-group boundaries, patching/backup ownership, encryption, "
            "tenant-aware database metrics, and EC2/EBS cost attribution."
        )
    if "eks" in services and services.intersection({"aurora", "rds"}) and control_id in {
        "TAI-03",
        "TAI-04",
        "ITC-03",
        "OOR-01",
        "OOR-03",
    }:
        notes.append(
            "For the detected EKS and Aurora/RDS stack, validate namespace or pod isolation, "
            "service-account IAM roles, row-level security or schema separation, cluster "
            "observability, and tenant-aware database metrics."
        )
    if "s3" in services and control_id in {"TAI-03", "OOR-01", "CAM-06"}:
        notes.append(
            "For S3-backed tenant data, validate bucket or prefix strategy, tenant-scoped IAM "
            "conditions, KMS key policy boundaries, lifecycle/retention rules, storage metrics, "
            "and request/storage cost attribution."
        )
    if "kms" in services and control_id in {"TAI-02", "TAI-03", "TAI-06"}:
        notes.append(
            "For KMS, validate whether keys, aliases, grants, and encryption context enforce "
            "the intended tenant or tier boundary."
        )
    if "elasticache" in services and control_id in {"TAI-04", "OOR-03", "CAM-06"}:
        notes.append(
            "For ElastiCache or Redis-style shared caches, validate tenant key namespaces, "
            "memory/eviction isolation, hot-key detection, and tenant-aware cache usage metrics."
        )
    if "opensearch" in services and control_id in {"TAI-03", "OOR-01", "CAM-06"}:
        notes.append(
            "For OpenSearch, validate tenant index or document-level separation, query filters, "
            "dashboard access boundaries, and tenant-level storage/query cost signals."
        )
    if services.intersection(MESSAGING_SERVICES) and control_id in {"ITC-02", "OOR-05", "CAM-02"}:
        notes.append(
            "For messaging/event services, validate that tenant context is carried in messages "
            "or events, consumers preserve it, failures are tenant-impact aware, and usage "
            "events can support metering where relevant."
        )
    if "ecs" in services and control_id in {"TAI-04", "DPA-02", "OOR-03"}:
        notes.append(
            "For ECS, validate task roles, service autoscaling, CPU/memory limits, deployment "
            "strategy, and tenant-aware service metrics."
        )
    if "redshift" in services and control_id in {"TAI-03", "CAM-06", "OOR-01"}:
        notes.append(
            "For Redshift, validate schema or row-level tenant controls, workload management, "
            "tenant-aware query/storage metrics, and cost allocation for shared analytics."
        )
    return notes


def routing_recommendations(
    dimensions: tuple[DimensionResult, ...],
    business_context: BusinessContext,
    facts: Mapping[str, Any],
) -> tuple[str, ...]:
    """Point to a deeper AWS/TAM engagement only when findings actually warrant it.

    Per the design notes, this agent is standalone and must not act like a
    funnel: each route below only fires on a specific weak-score-plus-context
    condition (e.g. weak isolation AND identity scores together, not either
    alone), so a customer with strong fundamentals sees no routing at all
    rather than a generic "talk to your TAM" footer.
    """

    by_id = {dimension.id: dimension for dimension in dimensions}
    routes: list[str] = []

    if score_at_or_below(by_id, ("TAI", "ITC"), 2.0):
        routes.append(
            "A formal AWS Well-Architected SaaS Lens review is the recommended next step "
            "for deeper workload-level validation of tenant isolation and tenant context. "
            "Use the currently approved review mechanism; do not assume SaaS Lens support "
            "in the AWS Well-Architected Agent at launch."
        )
    if score_at_or_below(by_id, ("OOR", "DPA"), 2.0) and business_context.stage in {
        "early_customers",
        "scaling",
        "mature",
    }:
        routes.append(
            "Consider an AWS Well-Architected Framework Review when production readiness, "
            "operations, or deployment controls need deeper review."
        )
    if signal_detected(facts, "iac") and not score_at_or_below(by_id, ("DPA",), 2.0):
        routes.append("If IaC coverage is strong, consider whether Automated SMA is a suitable deeper path.")
    if score_at_or_below(by_id, ("SBR", "CAM"), 2.0):
        routes.append(
            "A TAM-led SaaS Maturity Assessment or SaaS Compass/Factory engagement can "
            "help align packaging, pricing, service ownership, and unit economics."
        )
    return tuple(dict.fromkeys(routes))


def advisory_overlays(facts: Mapping[str, Any]) -> tuple[str, ...]:
    """Flag AI/ML presence as advisory-only, never as a scoring input.

    The rubric is explicit that AI/ML usage must not reward or penalize the
    default maturity score by its presence alone - so this only ever
    returns a note pointing at the optional overlay, and never touches any
    dimension/control score.
    """

    services = set(service_names(facts))
    if services.intersection(AI_ML_SERVICES):
        return (
            "AI/ML services were detected. Run the optional AI/ML advisory overlay for tenant "
            "data isolation, responsible operation, MLOps, and AI/ML cost attribution. This "
            "overlay does not affect default SaaS maturity scoring.",
        )
    return ()


def evidence_gaps(dimensions: tuple[DimensionResult, ...]) -> tuple[str, ...]:
    """List every control still `unknown`, for the report's "Evidence Gaps" section.

    Only `unknown` controls are gaps here - `missing` is a confirmed finding
    (the capability was checked and isn't there), while `unknown` means the
    assessment simply couldn't tell, which is the specific thing a customer
    can resolve by answering a question or granting a permission.
    """

    gaps = []
    for dimension in dimensions:
        for control in dimension.controls:
            if control.status != "unknown":
                continue
            if control.evidence_summary == "No evidence supplied.":
                gaps.append(f"{control.id}: {control.title}")
            else:
                gaps.append(f"{control.id}: {control.title} - {control.evidence_summary}")
    return tuple(gaps)


def overall_confidence(dimensions: tuple[DimensionResult, ...]) -> str:
    """Same high/medium/low rollup as dimension_confidence(), one level up.

    Deliberately a plain average of each dimension's already-computed
    confidence rather than re-deriving from every control directly - the
    unknown-ratio penalty already happened once per dimension, so repeating
    it here would double-count evidence gaps that span multiple dimensions.
    """

    if not dimensions:
        return "low"
    average = sum(CONFIDENCE_WEIGHTS[dimension.confidence] for dimension in dimensions) / len(dimensions)
    if average >= 0.75:
        return "high"
    if average >= 0.5:
        return "medium"
    return "low"


def build_coverage(dimensions: tuple[DimensionResult, ...]) -> CoverageResult:
    """Describe assessment breadth without modifying scores or confidence."""

    controls = [control for dimension in dimensions for control in dimension.controls]
    total = len(controls)
    assessed = sum(1 for control in controls if control.status != "unknown")
    scoreable = sum(1 for control in controls if control.score is not None)
    unknown = sum(1 for control in controls if control.status == "unknown")
    not_applicable = sum(
        1 for control in controls if control.status == "not_applicable"
    )
    ratio = round(assessed / total, 2) if total else 0.0
    all_dimensions_scored = all(dimension.score is not None for dimension in dimensions)
    report_status = (
        "baseline"
        if ratio >= BASELINE_COVERAGE_THRESHOLD and all_dimensions_scored
        else "provisional"
    )

    source_counts = {
        "customer_input": 0,
        "discovery_or_fact_signal": 0,
        "applicability_decision": 0,
        "explicit_evidence": 0,
        "unassessed": 0,
    }
    for control in controls:
        if control.status == "unknown":
            source_counts["unassessed"] += 1
        elif control.evidence_source in {"business-context", "business-question"}:
            source_counts["customer_input"] += 1
        elif control.evidence_source == "aws-discovery" or control.evidence_source.startswith(
            "fact-signal:"
        ):
            source_counts["discovery_or_fact_signal"] += 1
        elif control.evidence_source == "applicability":
            source_counts["applicability_decision"] += 1
        else:
            source_counts["explicit_evidence"] += 1

    return CoverageResult(
        report_status=report_status,
        assessed_controls=assessed,
        total_controls=total,
        scoreable_controls=scoreable,
        unknown_controls=unknown,
        not_applicable_controls=not_applicable,
        coverage_ratio=ratio,
        evidence_source_counts=source_counts,
    )


def dimension_score_rationale(dimension: DimensionResult) -> str:
    """Explain the exact control-status composition behind a dimension score."""

    counts = {
        status: sum(1 for control in dimension.controls if control.status == status)
        for status in VALID_STATUSES
    }
    if dimension.score is None:
        return (
            "No met, partial, or missing controls were available, so this dimension "
            f"was not scored; {counts['unknown']} remain unknown and "
            f"{counts['not_applicable']} are not applicable."
        )
    return (
        f"{counts['met']} met, {counts['partial']} partial, and {counts['missing']} "
        f"missing controls produced this score; {counts['unknown']} unknown and "
        f"{counts['not_applicable']} not-applicable controls were excluded."
    )


def dimension_customer_explanation(dimension: DimensionResult) -> dict[str, Any]:
    """Turn control evidence into a customer-facing explanation of the score.

    Status counts remain useful for audit data, but customers need the actual
    observed strengths, risks, and gaps that produced the score. This helper
    stays deterministic and only rephrases existing control evidence.
    """

    strengths = [control for control in dimension.controls if control.status == "met"]
    partials = [control for control in dimension.controls if control.status == "partial"]
    blockers = [control for control in dimension.controls if control.status == "missing"]
    unknowns = [control for control in dimension.controls if control.status == "unknown"]
    selected = (blockers + partials + strengths)[:3]
    source_ids: list[str] = []
    for control in selected:
        for source_id in control.sources:
            if source_id not in source_ids:
                source_ids.append(source_id)

    strength_text = tuple(
        f"{control.title}: {control.evidence_summary}" for control in strengths[:2]
    )
    partial_text = tuple(
        f"{control.title}: {control.evidence_summary}" for control in partials[:2]
    )
    blocker_text = tuple(
        f"{control.title}: {control.evidence_summary}" for control in blockers[:2]
    )
    gap_text = tuple(control.title for control in unknowns[:2])

    if dimension.score is None:
        summary = (
            "This dimension is not scored because the assessment has not yet gathered "
            "enough evidence. Confirm the listed gaps with the relevant persona, documents, "
            "or observed AWS signals before drawing a maturity conclusion."
        )
    elif blocker_text:
        foundation = partials[0] if partials else strengths[0] if strengths else None
        foundation_summary = (
            f"Evidence shows a partial foundation: {foundation.evidence_summary} "
            if foundation is not None
            else ""
        )
        risk_summary = " ".join(control.evidence_summary for control in blockers[:2])
        summary = f"{foundation_summary}The score is held back because {risk_summary}"
        if gap_text:
            summary += " Additional validation is still needed for the listed gaps."
    elif partial_text:
        summary = (
            f"The dimension has partial foundations: {partials[0].evidence_summary} "
            "More implementation evidence and the remaining gaps must be resolved before it can be treated as mature."
        )
    elif strength_text:
        summary = (
            f"Evidence shows that {strengths[0].evidence_summary} "
            "Remaining gaps still need technical validation before this can be treated as mature."
        )
    else:
        summary = "No scored customer evidence was available for this dimension."

    return {
        "summary": summary,
        "strengths": strength_text,
        "partials": partial_text,
        "blockers": blocker_text,
        "gaps": gap_text,
        "source_ids": tuple(source_ids),
    }


def primary_engagement_route(result: AssessmentResult) -> str | None:
    """Return the highest-priority deeper engagement, if one was triggered."""

    return result.routing_recommendations[0] if result.routing_recommendations else None


def render_html_report(result: AssessmentResult, redactor: Redactor | None = None) -> str:
    sanitizer = redactor or Redactor()
    coverage = result.coverage
    status_note = (
        "This is an evidence-backed baseline across all seven dimensions."
        if coverage.report_status == "baseline"
        else "This score is directional until coverage reaches 70% across all seven dimensions."
    )

    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(result.assessment_id)} SaaS Readiness</title>",
        "<style>",
        css(),
        "</style>",
        "</head>",
        "<body>",
        '<main class="shell">',
        "<header>",
        '<p class="eyebrow">SaaS Readiness Snapshot</p>',
        f"<h1>{escape(result.assessment_id)}</h1>",
        f'<p class="subtle">Generated {escape(result.generated_at)}. Evidence-first Level 0 assessment.</p>',
        "</header>",
        '<section class="summary-grid" aria-label="Assessment summary">',
        summary_card("Assessment Status", coverage.report_status.title(), status_note),
        summary_card("Overall Maturity", format_score(result.overall_score), maturity_label(result.overall_score)),
        summary_card(
            "Evidence Coverage",
            f"{coverage.assessed_controls}/{coverage.total_controls}",
            f"{coverage.coverage_ratio:.0%} of controls assessed",
        ),
        summary_card("Confidence", result.overall_confidence.title(), "Evidence quality across all dimensions"),
        "</section>",
        '<section class="panel">',
        "<h2>Read This First</h2>",
        f"<p><strong>{escape(coverage.report_status.title())}:</strong> {escape(status_note)}</p>",
        f"<p>{escape(plain_language_summary(result))}</p>",
        f"<p>{escape(score_explanation(result))}</p>",
        f'<p class="muted">Scope: {escape(result.scope.scope_type)} ({escape(result.scope.access_mode)}); '
        + f"stage: {escape(result.business_context.stage)}; tenancy: {escape(result.business_context.tenancy_model)}.</p>",
        "</section>",
        '<section class="panel">',
        "<h2>Evidence Coverage</h2>",
        f"<p>{coverage.scoreable_controls} scoreable, {coverage.not_applicable_controls} not applicable, "
        + f"and {coverage.unknown_controls} unknown controls.</p>",
        unordered_list(
            tuple(
                f"{key.replace('_', ' ').title()}: {value} controls"
                for key, value in coverage.evidence_source_counts.items()
            )
        ),
        "</section>",
        '<section class="panel" aria-labelledby="maturity-profile-title">',
        '<h2 id="maturity-profile-title">SaaS Maturity Profile</h2>',
        '<p class="muted">Scores are shown with confidence and assessed-control count. A not-scored dimension is not treated as zero.</p>',
        maturity_profile_chart(result),
        "</section>",
        '<section class="panel" aria-labelledby="evidence-coverage-chart-title">',
        '<h2 id="evidence-coverage-chart-title">Evidence Coverage by Dimension</h2>',
        '<p class="muted">Each bar shows the assessed, unknown, and not-applicable control mix for that dimension.</p>',
        evidence_coverage_chart(result),
        "</section>",
        "<section>",
        "<h2>Seven-Dimension Summary</h2>",
        '<div class="dimension-grid">',
    ]
    lines.extend(
        dimension_summary_card(dimension, result) for dimension in result.dimensions
    )
    lines.extend(["</div>", "</section>"])

    lines.extend(["<section>", "<h2>Now / Next / Later</h2>", '<div class="action-grid">'])
    horizons = ("Now", "Next", "Later")
    for horizon, recommendation in zip(horizons, result.top_recommendations[:3]):
        lines.append(front_door_recommendation_card(horizon, recommendation, result))
    if not result.top_recommendations:
        lines.append('<article class="card"><p>No recommendations were generated.</p></article>')
    lines.extend(["</div>", "</section>"])

    route = primary_engagement_route(result)
    lines.extend(
        [
            '<section class="panel">',
            "<h2>Primary Engagement Route</h2>",
            f"<p>{escape(route or 'No deeper-assessment route was triggered.')}</p>",
            "</section>",
            '<section class="panel appendix">',
            "<h2>Appendix</h2>",
            "<h3>Environment and Service Observations</h3>",
            unordered_list(
                result.input_observations
                + result.service_observations
                or ("No AWS/account fact summary was supplied.",)
            ),
            "<h3>All Controls</h3>",
        ]
    )
    lines.extend(dimension_section(dimension, result) for dimension in result.dimensions)
    lines.extend(
        [
            "<h3>All Evidence Gaps</h3>",
            unordered_list(result.evidence_gaps),
            "<h3>Methodology</h3>",
            methodology_html(),
            "<h3>Public AWS References</h3>",
            source_catalog_html(result),
        ]
    )
    if result.advisory_overlays:
        lines.extend(["<h3>Optional Advisory Overlays</h3>", unordered_list(result.advisory_overlays)])
    lines.extend(
        [
            "<h3>Disclaimers</h3>",
            unordered_list(result.disclaimers),
            "</section>",
            "</main>",
            "</body>",
            "</html>",
        ]
    )
    return sanitizer.sanitize_text("\n".join(lines) + "\n")


def css() -> str:
    return """
:root {
  color-scheme: dark;
  --bg: #0b0f14;
  --panel: #131a22;
  --panel-soft: #18212b;
  --border: #2b3847;
  --text: #eef3f8;
  --muted: #aab7c4;
  --accent: #6fd4c5;
  --amber: #f2b84b;
  --red: #ff786f;
  --green: #84d987;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.55;
}
.shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 40px 0 64px; }
header { margin-bottom: 28px; }
h1, h2, h3, h4, p { margin-top: 0; }
h1 { font-size: clamp(2rem, 4vw, 4rem); line-height: 1; margin-bottom: 12px; }
h2 { font-size: 1.45rem; margin-bottom: 16px; }
h3 { font-size: 1.05rem; margin-bottom: 8px; }
h4 { font-size: 0.95rem; margin-bottom: 6px; }
a { color: var(--accent); }
.eyebrow { color: var(--accent); text-transform: uppercase; font-size: 0.78rem; font-weight: 700; }
.subtle, .muted { color: var(--muted); }
.summary-grid, .action-grid, .dimension-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.action-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.dimension-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.panel, .card, .dimension {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px;
  margin-bottom: 16px;
}
details.card > summary {
  cursor: pointer;
  list-style: none;
  margin: -18px -18px 0;
  padding: 18px;
  border-radius: 8px;
}
details.card > summary::-webkit-details-marker { display: none; }
details.card > summary::after {
  content: "Click to expand details \2193";
  display: block;
  margin-top: 10px;
  color: var(--accent);
  font-size: 0.8rem;
  text-transform: none;
  font-weight: 500;
}
details.card[open] > summary::after { content: "Click to collapse \2191"; }
details.card[open] > summary { margin-bottom: 0; }
details.card > summary:hover { background: var(--panel-soft); }
details.card > summary > *:last-child { margin-bottom: 0; }
details.card > *:not(summary) { margin-top: 14px; }
.summary-card { min-height: 132px; }
.metric { font-size: 1.8rem; font-weight: 750; margin-bottom: 6px; }
.tag {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 2px 9px;
  color: var(--muted);
  font-size: 0.78rem;
  text-transform: uppercase;
}
.status-met { color: var(--green); }
.status-partial { color: var(--amber); }
.status-missing { color: var(--red); }
.status-unknown { color: var(--muted); }
.status-not_applicable { color: var(--muted); }
.controls { display: grid; gap: 10px; margin-top: 14px; }
.control {
  background: var(--panel-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
}
.control-grid { display: grid; grid-template-columns: 180px 1fr; gap: 8px 16px; margin-top: 10px; }
.label { color: var(--muted); font-size: 0.82rem; text-transform: uppercase; }
ul { padding-left: 20px; margin-bottom: 0; }
li + li { margin-top: 8px; }
.source-list { margin-top: 8px; color: var(--muted); font-size: 0.9rem; }
.chart { display: grid; gap: 12px; }
.chart-row { display: grid; grid-template-columns: minmax(210px, 0.9fr) minmax(240px, 2fr) 115px; gap: 12px; align-items: center; }
.chart-label { font-size: 0.92rem; font-weight: 650; }
.chart-value { font-size: 0.9rem; text-align: right; font-weight: 650; }
.chart-value span { color: var(--muted); font-size: 0.78rem; font-weight: 400; }
.bar-track, .coverage-track { display: flex; min-height: 22px; overflow: hidden; border: 1px solid var(--border); border-radius: 999px; background: var(--panel-soft); }
.bar-score { background: linear-gradient(90deg, #2e897f, var(--accent)); }
.bar-unscored { width: 100%; display: flex; align-items: center; padding-left: 10px; color: var(--muted); border: 1px dashed var(--muted); border-radius: 999px; }
.coverage-met { background: var(--green); }
.coverage-partial { background: var(--amber); }
.coverage-missing { background: var(--red); }
.coverage-unknown { background: #677484; }
.coverage-na { background: #537ea8; }
.chart-legend { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; color: var(--muted); font-size: 0.8rem; }
.chart-legend span { display: inline-flex; align-items: center; gap: 5px; }
.chart-legend i { width: 10px; height: 10px; border-radius: 2px; }
.legend-met { background: var(--green); }
.legend-partial { background: var(--amber); }
.legend-missing { background: var(--red); }
.legend-unknown { background: #677484; }
.legend-na { background: #537ea8; }
@media (max-width: 900px) {
  .summary-grid, .action-grid, .dimension-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .shell { width: min(100% - 20px, 1180px); padding-top: 24px; }
  .summary-grid, .action-grid, .dimension-grid, .control-grid, .chart-row { grid-template-columns: 1fr; }
  .chart-value { text-align: left; }
}
""".strip()


def summary_card(title: str, metric: str, note: str) -> str:
    return (
        '<article class="card summary-card">'
        f"<h2>{escape(title)}</h2>"
        f'<p class="metric">{escape(metric)}</p>'
        f'<p class="muted">{escape(note)}</p>'
        "</article>"
    )


def dimension_status_counts(dimension: DimensionResult) -> dict[str, int]:
    """Count controls by assessment state for an evidence-coverage chart."""

    return {
        status: sum(1 for control in dimension.controls if control.status == status)
        for status in ("met", "partial", "missing", "unknown", "not_applicable")
    }


def maturity_profile_chart(result: AssessmentResult) -> str:
    """Render the seven-dimension score profile without external JavaScript."""

    rows = ['<div class="chart" role="list">']
    for dimension in result.dimensions:
        assessed = sum(1 for control in dimension.controls if control.status != "unknown")
        if dimension.score is None:
            bar = '<div class="bar-track"><div class="bar-unscored">Not scored</div></div>'
            score_text = "not scored"
        else:
            percent = max(0.0, min(100.0, dimension.score / 5 * 100))
            bar = (
                '<div class="bar-track">'
                f'<div class="bar-score" style="width:{percent:.1f}%"></div>'
                "</div>"
            )
            score_text = format_score(dimension.score)
        rows.append(
            '<div class="chart-row" role="listitem">'
            f'<div class="chart-label">{escape(dimension.name)}</div>'
            f'<div role="img" aria-label="{escape(dimension.name)}: {escape(score_text)}, '
            f'{escape(dimension.confidence)} confidence, {assessed} of {len(dimension.controls)} controls assessed.">{bar}</div>'
            f'<div class="chart-value">{escape(score_text)}<br><span>{escape(dimension.confidence)} · {assessed}/{len(dimension.controls)}</span></div>'
            "</div>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def evidence_coverage_chart(result: AssessmentResult) -> str:
    """Render status coverage so scores are not mistaken for complete evidence."""

    rows = [
        (
            '<div class="chart-legend" aria-label="Evidence coverage legend">'
            + '<span><i class="legend-met"></i>Met</span>'
            + '<span><i class="legend-partial"></i>Partial</span>'
            + '<span><i class="legend-missing"></i>Missing</span>'
            + '<span><i class="legend-unknown"></i>Unknown</span>'
            + '<span><i class="legend-na"></i>Not applicable</span>'
            + "</div>"
        ),
        '<div class="chart" role="list">',
    ]
    for dimension in result.dimensions:
        counts = dimension_status_counts(dimension)
        total = len(dimension.controls)
        segments = []
        for status, css_class in (
            ("met", "coverage-met"),
            ("partial", "coverage-partial"),
            ("missing", "coverage-missing"),
            ("unknown", "coverage-unknown"),
            ("not_applicable", "coverage-na"),
        ):
            if counts[status]:
                width = counts[status] / total * 100
                segments.append(
                    f'<span class="{css_class}" style="width:{width:.1f}%"></span>'
                )
        assessed = total - counts["unknown"]
        label = (
            f"{dimension.name}: {assessed} of {total} controls assessed; "
            f"{counts['met']} met, {counts['partial']} partial, {counts['missing']} missing, "
            f"{counts['unknown']} unknown, and {counts['not_applicable']} not applicable."
        )
        rows.append(
            '<div class="chart-row" role="listitem">'
            f'<div class="chart-label">{escape(dimension.name)}</div>'
            f'<div class="coverage-track" role="img" aria-label="{escape(label)}">'
            f"{''.join(segments)}</div>"
            f'<div class="chart-value">{assessed}/{total}<br><span>assessed</span></div>'
            "</div>"
        )
    rows.append("</div>")
    return "\n".join(rows)


def dimension_summary_card(dimension: DimensionResult, result: AssessmentResult) -> str:
    assessed = sum(1 for control in dimension.controls if control.status != "unknown")
    explanation = dimension_customer_explanation(dimension)
    sections = [
        '<details class="card">',
        "<summary>",
        f"<h3>{escape(dimension.name)}</h3>",
        f'<p class="metric">{escape(format_score(dimension.score))}</p>',
        f'<p class="muted">Confidence: {escape(dimension.confidence)}; '
        + f"{assessed}/{len(dimension.controls)} controls assessed.</p>",
        "</summary>",
        f"<p><strong>Why this matters:</strong> {escape(dimension.why)}</p>",
        f"<p><strong>Why this score:</strong> {escape(explanation['summary'])}</p>",
    ]
    if explanation["strengths"]:
        sections.extend(
            [
                "<h4>What is working</h4>",
                unordered_list(explanation["strengths"]),
            ]
        )
    if explanation["partials"]:
        sections.extend(
            [
                "<h4>Partial foundations</h4>",
                unordered_list(explanation["partials"]),
            ]
        )
    if explanation["blockers"]:
        sections.extend(
            [
                "<h4>What needs attention</h4>",
                unordered_list(explanation["blockers"]),
            ]
        )
    if explanation["gaps"]:
        sections.extend(
            [
                "<h4>Still to validate</h4>",
                unordered_list(explanation["gaps"]),
            ]
        )
    sections.append(
        f'<p class="source-list">AWS guidance: {source_links(explanation["source_ids"], result)}</p>'
    )
    sections.append("</details>")
    return "\n".join(sections)


def find_control(result: AssessmentResult, control_id: str) -> ControlResult | None:
    for dimension in result.dimensions:
        for control in dimension.controls:
            if control.id == control_id:
                return control
    return None


def front_door_recommendation_card(
    horizon: str, recommendation: RecommendationResult, result: AssessmentResult
) -> str:
    control = find_control(result, recommendation.control_id)
    evidence = control.evidence_summary if control else "No evidence summary available."
    source = control.evidence_source if control else "unknown"
    return (
        '<details class="card">'
        "<summary>"
        f'<span class="tag">{escape(horizon)}</span>'
        f"<h3>{escape(recommendation.control_id)}: {escape(recommendation.title)}</h3>"
        f'<p class="{status_class(recommendation.status)}">'
        f"Priority: {escape(recommendation.priority)}; status: {escape(recommendation.status)}; "
        f"confidence: {escape(recommendation.confidence)}</p>"
        "</summary>"
        f"<p>{escape(recommendation.action)}</p>"
        f'<p class="source-list">Triggered by ({escape(source)}): {escape(evidence)}</p>'
        f'<p class="source-list">AWS references: {source_links(recommendation.sources, result)}</p>'
        "</details>"
    )


def methodology_html() -> str:
    return unordered_list(
        (
            "Control scoring: met=1, partial=0.5, missing=0; unknown and not applicable are excluded.",
            "Dimension scores average scoreable controls and scale the result to five.",
            "Overall maturity is a weighted average with gates for weak SaaS fundamentals and sparse evidence.",
            "Baseline status requires at least 70% coverage and a score in all seven dimensions.",
            "Customer assertions can identify partial or missing capabilities but cannot prove technical controls are met.",
            "Recommendations are ranked deterministically; the report presents the first three as Now, Next, and Later.",
        )
    )


def source_catalog_html(result: AssessmentResult) -> str:
    lines = ["<ul>"]
    for source_id, source in result.source_catalog.items():
        title = escape(source.get("title", source_id))
        url = html.escape(source.get("url", ""), quote=True)
        lines.append(f'<li><a href="{url}">{title}</a></li>')
    lines.append("</ul>")
    return "\n".join(lines)


def recommendation_card(recommendation: RecommendationResult, result: AssessmentResult) -> str:
    service_notes = unordered_list(recommendation.service_notes) if recommendation.service_notes else ""
    return (
        '<article class="card">'
        f'<span class="tag">{escape(recommendation.priority)}</span>'
        f"<h3>{escape(recommendation.control_id)}: {escape(recommendation.title)}</h3>"
        f'<p class="{status_class(recommendation.status)}">'
        f"Status: {escape(recommendation.status)}; confidence: {escape(recommendation.confidence)}</p>"
        f"<p>{escape(recommendation.action)}</p>"
        f"{service_notes}"
        f'<p class="source-list">Sources: {source_links(recommendation.sources, result)}</p>'
        "</article>"
    )


def dimension_section(dimension: DimensionResult, result: AssessmentResult) -> str:
    lines = [
        '<section class="dimension">',
        f"<h3>{escape(dimension.name)}</h3>",
        f'<p class="metric">{escape(format_score(dimension.score))}</p>',
        f'<p class="muted">Confidence: {escape(dimension.confidence)}. {escape(dimension.why)}</p>',
        f'<p class="muted">Customer question: {escape(dimension.customer_question)}</p>',
        '<div class="controls">',
    ]
    for control in dimension.controls:
        lines.append(control_block(control, result))
    lines.extend(["</div>", "</section>"])
    return "\n".join(lines)


def control_block(control: ControlResult, result: AssessmentResult) -> str:
    return (
        '<article class="control">'
        f"<h4>{escape(control.id)}: {escape(control.title)}</h4>"
        '<div class="control-grid">'
        '<div class="label">Status</div>'
        f'<div class="{status_class(control.status)}">{escape(control.status)}</div>'
        '<div class="label">Confidence</div>'
        f"<div>{escape(control.confidence)}; evidence state: {escape(control.evidence_state)}</div>"
        '<div class="label">Observed Evidence</div>'
        f"<div>{escape(control.evidence_summary)}</div>"
        '<div class="label">Why It Matters</div>'
        f"<div>{escape(control.why)}</div>"
        '<div class="label">Recommendation</div>'
        f"<div>{escape(control.recommendation)}</div>"
        '<div class="label">Sources</div>'
        f"<div>{source_links(control.sources, result)}</div>"
        "</div>"
        "</article>"
    )


def unordered_list(items: tuple[str, ...] | list[str]) -> str:
    if not items:
        return "<ul><li>None.</li></ul>"
    lines = ["<ul>"]
    lines.extend(f"<li>{escape(str(item))}</li>" for item in items)
    lines.append("</ul>")
    return "\n".join(lines)


def source_links(source_ids: tuple[str, ...], result: AssessmentResult) -> str:
    links = []
    for source_id in source_ids:
        source = result.source_catalog.get(source_id)
        if not source:
            links.append(escape(source_id))
            continue
        title = escape(source.get("title", source_id))
        url = html.escape(source.get("url", ""), quote=True)
        links.append(f'<a href="{url}">{title}</a>')
    return "; ".join(links) if links else "No public source mapped."


def write_html_report(path: Path, result: AssessmentResult, redactor: Redactor | None = None) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html_report(result, redactor), encoding="utf-8")
    except OSError as exc:
        raise OutputFileError(f"Could not write HTML report to {path}.", detail=str(exc)) from exc


def write_json_debug(path: Path, result: AssessmentResult, redactor: Redactor | None = None) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (redactor or Redactor()).sanitize(to_plain(result))
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise OutputFileError(f"Could not write debug JSON to {path}.", detail=str(exc)) from exc


def write_assessment_json(path: Path, result: AssessmentResult, redactor: Redactor | None = None) -> None:
    """Write the canonical machine-readable assessment.json artifact.

    This is the same shape as --json-debug (kept for backward compatibility
    with existing tooling/tests) but under the name the design notes specify
    as the primary machine-readable output artifact.
    """

    write_json_debug(path, result, redactor)


def build_findings_list(result: AssessmentResult) -> list[dict[str, Any]]:
    """Flatten every scored control into the normalized findings shape.

    Field names follow the design notes' findings.json spec exactly:
    dimension, status, evidence_state, why_it_matters, metric_rationale,
    evidence, recommended_next_step, source_refs, source_ref_claim.
    `source_ref_claim` is derived from the control's `why` text because that
    is the specific principle each source reference is meant to support -
    the rubric does not carry a separate claim string per source, so reusing
    `why` keeps the claim grounded in the same rationale shown in the report
    rather than inventing new text.
    """

    horizons = {
        recommendation.control_id: horizon
        for horizon, recommendation in zip(
            ("Now", "Next", "Later"), result.top_recommendations[:3]
        )
    }
    findings: list[dict[str, Any]] = []
    for dimension in result.dimensions:
        for control in dimension.controls:
            findings.append(
                {
                    "control_id": control.id,
                    "dimension": dimension.name,
                    "dimension_id": dimension.id,
                    "title": control.title,
                    "status": control.status,
                    "score": control.score,
                    "confidence": control.confidence,
                    "evidence_state": control.evidence_state,
                    "why_it_matters": control.why,
                    "metric_rationale": dimension.why,
                    "evidence": control.evidence_summary,
                    "evidence_source": control.evidence_source,
                    "recommended_next_step": control.recommendation,
                    "source_refs": list(control.sources),
                    "source_ref_claim": control.why,
                    "assessed": control.status != "unknown",
                    "score_rationale": dimension_score_rationale(dimension),
                    "is_top_action": control.id in horizons,
                    "action_horizon": horizons.get(control.id),
                    "public_source_refs": [
                        {
                            "id": source_id,
                            "title": result.source_catalog.get(source_id, {}).get(
                                "title", source_id
                            ),
                            "url": result.source_catalog.get(source_id, {}).get("url", ""),
                        }
                        for source_id in control.sources
                    ],
                }
            )
    return findings


def write_findings_json(path: Path, result: AssessmentResult, redactor: Redactor | None = None) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        sanitizer = redactor or Redactor()
        payload = sanitizer.sanitize(build_findings_list(result))
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise OutputFileError(f"Could not write findings JSON to {path}.", detail=str(exc)) from exc


def markdown_source_links(source_ids: tuple[str, ...], result: AssessmentResult) -> str:
    links = []
    for source_id in source_ids:
        source = result.source_catalog.get(source_id, {})
        title = source.get("title", source_id)
        url = source.get("url", "")
        links.append(f"[{title}]({url})" if url else title)
    return "; ".join(links) if links else "No public source mapped."


def build_summary_markdown(
    result: AssessmentResult, explanation: ExplanationBundle | None = None
) -> str:
    """Build the concise front-door report plus a complete audit appendix."""

    coverage = result.coverage
    status_note = (
        "Evidence-backed baseline across all seven dimensions."
        if coverage.report_status == "baseline"
        else "Directional until coverage reaches 70% across all seven dimensions."
    )
    lines = [
        f"# SaaS Readiness Snapshot: {result.assessment_id}",
        "",
        f"Generated {result.generated_at}. Evidence-first Level 0 assessment.",
        "",
        "## Assessment Status",
        "",
        f"- Status: **{coverage.report_status.title()}** — {status_note}",
        f"- Overall maturity: **{format_score(result.overall_score)}** ({maturity_label(result.overall_score)})",
        f"- Confidence: **{result.overall_confidence}**",
        f"- Coverage: **{coverage.assessed_controls}/{coverage.total_controls} controls** ({coverage.coverage_ratio:.0%})",
        f"- Scope: {result.scope.scope_type} ({result.scope.access_mode})",
        f"- Context: stage={result.business_context.stage}; segment={result.business_context.target_segment}; tenancy={result.business_context.tenancy_model}",
        "",
        plain_language_summary(result),
        "",
    ]
    if explanation and explanation.executive_summary:
        lines.extend([explanation.executive_summary, ""])

    lines.extend(["## Evidence Coverage", ""])
    lines.append(
        f"{coverage.scoreable_controls} scoreable, {coverage.not_applicable_controls} not applicable, "
        f"and {coverage.unknown_controls} unknown controls."
    )
    lines.append("")
    for key, value in coverage.evidence_source_counts.items():
        lines.append(f"- {key.replace('_', ' ').title()}: {value}")
    lines.append("")

    lines.extend(["## Seven-Dimension Summary", ""])
    for dimension in result.dimensions:
        assessed = sum(1 for control in dimension.controls if control.status != "unknown")
        dimension_explanation = dimension_customer_explanation(dimension)
        lines.extend(
            [
                f"### {dimension.name} — {format_score(dimension.score)}",
                "",
                f"Confidence: {dimension.confidence}; {assessed}/{len(dimension.controls)} controls assessed.",
                "",
                f"**Why this matters:** {dimension.why}",
                "",
                f"**Why this score:** {dimension_explanation['summary']}",
                "",
            ]
        )
        if dimension_explanation["strengths"]:
            lines.extend(["**What is working**"])
            lines.extend(f"- {item}" for item in dimension_explanation["strengths"])
            lines.append("")
        if dimension_explanation["partials"]:
            lines.extend(["**Partial foundations**"])
            lines.extend(f"- {item}" for item in dimension_explanation["partials"])
            lines.append("")
        if dimension_explanation["blockers"]:
            lines.extend(["**What needs attention**"])
            lines.extend(f"- {item}" for item in dimension_explanation["blockers"])
            lines.append("")
        if dimension_explanation["gaps"]:
            lines.extend(["**Still to validate**"])
            lines.extend(f"- {item}" for item in dimension_explanation["gaps"])
            lines.append("")
        lines.append(
            f"**AWS guidance:** {markdown_source_links(dimension_explanation['source_ids'], result)}"
        )
        lines.append("")

    lines.extend(["## Now / Next / Later", ""])
    for horizon, recommendation in zip(("Now", "Next", "Later"), result.top_recommendations[:3]):
        control = find_control(result, recommendation.control_id)
        evidence = control.evidence_summary if control else "No evidence summary available."
        source = control.evidence_source if control else "unknown"
        lines.extend(
            [
                f"### {horizon}: {recommendation.control_id} — {recommendation.title}",
                "",
                recommendation.action,
                "",
                f"- Triggering evidence ({source}): {evidence}",
                f"- Status: {recommendation.status}; confidence: {recommendation.confidence}; priority: {recommendation.priority}",
                f"- AWS references: {markdown_source_links(recommendation.sources, result)}",
                "",
            ]
        )
    if not result.top_recommendations:
        lines.extend(["No recommendations were generated.", ""])

    route = primary_engagement_route(result)
    lines.extend(
        [
            "## Primary Engagement Route",
            "",
            route or "No deeper-assessment route was triggered.",
            "",
            "## Appendix",
            "",
            "### All Controls",
            "",
        ]
    )
    for dimension in result.dimensions:
        lines.append(f"#### {dimension.name}")
        lines.append("")
        for control in dimension.controls:
            lines.append(
                f"- **{control.id}** ({control.status}, {control.confidence} confidence; "
                f"source: {control.evidence_source}): {control.evidence_summary}"
            )
        lines.append("")

    lines.extend(["### Evidence Gaps", ""])
    lines.extend(f"- {gap}" for gap in result.evidence_gaps)
    if not result.evidence_gaps:
        lines.append("- None.")
    lines.extend(
        [
            "",
            "### Methodology",
            "",
            "- met=1, partial=0.5, missing=0; unknown and not applicable are excluded from score averages.",
            "- Dimension scores average scoreable controls and scale to five.",
            "- Overall maturity applies rubric weights and gates for weak fundamentals and sparse evidence.",
            "- Baseline status requires at least 70% coverage and a score in all seven dimensions.",
            "- Customer assertions cannot prove that technical controls are met.",
            "",
            "### Public AWS References",
            "",
        ]
    )
    for source_id, source_details in result.source_catalog.items():
        lines.append(
            f"- [{source_details.get('title', source_id)}]({source_details.get('url', '')})"
        )
    lines.extend(["", "### Disclaimers", ""])
    lines.extend(f"- {disclaimer}" for disclaimer in result.disclaimers)
    lines.append("")
    return "\n".join(lines)


def write_summary_markdown(
    path: Path,
    result: AssessmentResult,
    explanation: ExplanationBundle | None = None,
    redactor: Redactor | None = None,
) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        sanitizer = redactor or Redactor()
        path.write_text(sanitizer.sanitize_text(build_summary_markdown(result, explanation)), encoding="utf-8")
    except OSError as exc:
        raise OutputFileError(f"Could not write summary Markdown to {path}.", detail=str(exc)) from exc


def merge_aws_preflight(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Run the full read-only AWS discovery pipeline and merge results into the payload.

    Delegates all AWS API calls to discovery.run_aws_discovery (the only
    module allowed to import boto3). This function's job is limited to
    merging discovery output into the assessment input shape: prepending
    discovery evidence ahead of caller-supplied evidence (explicit evidence
    still wins on conflicts, per explicit_evidence's dict semantics) and
    merging discovered facts/signals with any facts already in the payload.
    """

    merged = dict(payload)
    scope = parse_scope(mapping(merged.get("scope")))
    discovery_facts, discovery_evidence, observations = run_aws_discovery(scope)

    existing_evidence = merged.get("evidence", [])
    if not isinstance(existing_evidence, list):
        existing_evidence = []
    merged["evidence"] = [to_plain(item) for item in discovery_evidence] + list(existing_evidence)

    facts = mapping(merged.get("facts"))
    merged_facts = merge_facts(facts, discovery_facts)
    if observations:
        merged_facts["discovery_observations"] = list(observations)
    merged["facts"] = merged_facts
    return merged


def merge_facts(existing: Mapping[str, Any], discovered: Mapping[str, Any]) -> dict[str, Any]:
    """Combine caller-supplied facts with live discovery output.

    `missing_permissions` is concatenated and de-duplicated (a permission
    gap from either source still counts), while `signals` uses dict.update()
    so a signal name present in both sources takes the discovered value -
    live discovery is assumed more current than facts supplied earlier in
    the same run.
    """

    merged = dict(existing)
    missing = list(string_list(fact(existing, "missing_permissions")))
    missing.extend(string_list(discovered.get("missing_permissions")))
    if missing:
        merged["missing_permissions"] = list(dict.fromkeys(missing))

    signals = mapping(existing.get("signals"))
    signals.update(mapping(discovered.get("signals")))
    if signals:
        merged["signals"] = signals
    return merged


def load_payload(base_dir: Path, path_value: str) -> dict[str, Any]:
    path = safe_path(base_dir, path_value, "input")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputFileError(f"Input file does not exist: {path}.") from exc
    except JSONDecodeError as exc:
        raise InputFileError(f"Input file {path} is not valid JSON.", detail=str(exc)) from exc
    except OSError as exc:
        raise InputFileError(f"Could not read input file {path}.", detail=str(exc)) from exc
    if not isinstance(payload, dict):
        raise ValidationError("Assessment input must be a JSON object.")
    return payload


def safe_path(base_dir: Path, path_value: str, label: str) -> Path:
    """Resolve a user-supplied path and reject anything outside base_dir.

    This is the project's only path-traversal guard, used for every
    input/output/session path the CLI accepts. `resolved.relative_to(base)`
    raises ValueError the moment the resolved path (after following `..`
    segments and symlinks) falls outside base_dir, which is what turns a
    `--output ../../etc/passwd`-style argument into a clean InputFileError
    instead of a write outside the project directory.
    """

    try:
        raw_path = Path(path_value).expanduser()
        base = base_dir.resolve()
        resolved = raw_path.resolve() if raw_path.is_absolute() else (base / raw_path).resolve()
        resolved.relative_to(base)
    except ValueError as exc:
        raise InputFileError(f"{label.capitalize()} path must stay inside {base_dir.resolve()}.") from exc
    except OSError as exc:
        raise InputFileError(f"Could not resolve {label} path {path_value}.", detail=str(exc)) from exc
    return resolved


def merge_session_answers(payload: Mapping[str, Any], session_store: SessionStore) -> dict[str, Any]:
    merged = dict(payload)
    business_context = mapping(merged.get("business_context"))
    existing = list(business_context.get("answers", ())) if isinstance(business_context.get("answers"), list) else []
    business_context["answers"] = existing + list(session_store.as_business_context_answers())
    merged["business_context"] = business_context
    return merged


def select_questions(result: AssessmentResult, answered: set[str], limit: int) -> list[dict[str, Any]]:
    """Select unresolved customer-facing AQ topics using their mapped BQ signals."""

    if limit == 0:
        return []

    weak_controls = {
        control.id
        for dimension in result.dimensions
        for control in dimension.controls
        if control.status in {"unknown", "missing", "partial"}
    }
    scored_questions: list[tuple[int, int, dict[str, Any]]] = []
    for index, question in enumerate(ADAPTIVE_QUESTIONS):
        scoring_ids = question.get("scoring_ids", {})
        if not isinstance(scoring_ids, Mapping):
            continue
        signal_ids = tuple(str(signal_id) for signal_id in scoring_ids)
        if signal_ids and all(signal_id in answered for signal_id in signal_ids):
            continue
        controls = tuple(str(control_id) for control_id in question.get("controls", ()))
        score = sum(2 if control_id in weak_controls else 0 for control_id in controls)
        if str(question.get("priority", "extended")) == "essential":
            score += 1
        scored_questions.append(
            (
                -score,
                index,
                {
                    "id": str(question["id"]),
                    "prompt": str(question["prompt"]),
                    "probes": list(question.get("probes", ())),
                    "persona": str(question.get("persona", "")),
                    "scoring_ids": dict(scoring_ids),
                    "controls": list(controls),
                    "options": sorted(
                        {
                            str(option)
                            for signal in scoring_ids.values()
                            if isinstance(signal, Mapping)
                            for option in signal.get("options", ())
                        }
                    ),
                },
            )
        )

    scored_questions.sort(key=lambda item: (item[0], item[1]))
    return [question for _, _, question in scored_questions[:limit]]


def answered_question_ids(payload: Mapping[str, Any]) -> set[str]:
    business_context = mapping(payload.get("business_context"))
    return set(answer_map(tuple_of_mappings(business_context.get("answers"))))


def parse_scope(value: Mapping[str, Any]) -> Scope:
    return Scope(
        assessment_id=str(value.get("assessment_id", "local-assessment")).strip() or "local-assessment",
        scope_type=str(value.get("scope_type", "single-account")).strip() or "single-account",
        access_mode=str(value.get("access_mode", "minimum_read_only")).strip() or "minimum_read_only",
        regions=tuple(str(region) for region in value.get("regions", ()) if str(region).strip()),
        notes=tuple(str(note) for note in value.get("notes", ()) if str(note).strip()),
    )


def parse_business_context(value: Mapping[str, Any]) -> BusinessContext:
    answers = tuple_of_mappings(value.get("answers"))
    mapped_answers = answer_map(answers)
    return BusinessContext(
        stage=first_known(value.get("stage"), mapped_answers.get("BQ-005")) or "unknown",
        target_segment=first_known(
            value.get("target_segment"), mapped_answers.get("BQ-006")
        )
        or "unknown",
        pricing_model=first_known(
            value.get("pricing_model"), mapped_answers.get("BQ-007")
        )
        or "unknown",
        tenancy_model=first_known(
            value.get("tenancy_model"), mapped_answers.get("BQ-001")
        )
        or "unknown",
        growth_pressure=first_known(
            value.get("growth_pressure"), mapped_answers.get("BQ-013")
        )
        or "unknown",
        answers=answers,
    )


def answer_map(answers: tuple[dict[str, Any], ...]) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for answer in answers:
        question_id = str(answer.get("question_id", answer.get("id", ""))).strip()
        answer_value = str(answer.get("answer_value", answer.get("value", ""))).strip()
        if question_id and answer_value:
            mapped[question_id] = answer_value
    return mapped


def mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def tuple_of_mappings(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, Mapping))


def fact(facts: Mapping[str, Any], key: str) -> Any:
    """Look up a fact, checking a nested `facts.aws.*` namespace as a fallback.

    Lets callers supply facts either flat (`facts.shared_resources`) or
    nested under an `aws` key (`facts.aws.shared_resources`), so input JSON
    that groups AWS-sourced facts together doesn't need to be flattened
    before it reaches this module.
    """

    if key in facts:
        return facts[key]
    aws = facts.get("aws")
    if isinstance(aws, Mapping) and key in aws:
        return aws[key]
    return None


def bool_fact(facts: Mapping[str, Any], key: str) -> bool | None:
    value = fact(facts, key)
    return value if isinstance(value, bool) else None


def signal(facts: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Normalize a named signal into the {"inspected": ..., "detected": ...} shape.

    Accepts three input shapes so callers (including discovery.py and
    hand-written sample JSON) don't all have to agree on one format: a full
    dict under `facts.signals.<name>`, a bare `bool` under either location
    (shorthand for "this was inspected and here's the result"), or nothing
    at all, which becomes `{"inspected": False}` - the signal was never
    checked, so every rule reading it should treat the control as unknown.
    """

    signals = facts.get("signals")
    raw_signal: Any = signals.get(name) if isinstance(signals, Mapping) else None
    if raw_signal is None:
        raw_signal = facts.get(name)
    if isinstance(raw_signal, bool):
        return {"inspected": True, "detected": raw_signal}
    return dict(raw_signal) if isinstance(raw_signal, Mapping) else {"inspected": False}


def signal_detected(facts: Mapping[str, Any], name: str) -> bool:
    item = signal(facts, name)
    return bool(item.get("detected"))


def signal_status(value: Any) -> str:
    # A True/False tenant-isolation-style signal never maps straight to
    # met/missing: even a confirmed "isolation detected" (True) still only
    # counts as `partial`, because the rubric requires stronger evidence
    # than one boolean signal before crediting a control as fully `met`.
    if value is True:
        return "partial"
    if value is False:
        return "missing"
    return "unknown"


def service_names(facts: Mapping[str, Any]) -> tuple[str, ...]:
    services = fact(facts, "services")
    if not isinstance(services, (list, tuple)):
        return ()
    return tuple(normalize_service_name(str(service)) for service in services if str(service).strip())


def normalize_service_name(service: str) -> str:
    lowered = service.strip().lower()
    return SERVICE_ALIASES.get(lowered, lowered)


def has_ec2_database_service(facts: Mapping[str, Any]) -> bool:
    services = set(service_names(facts))
    return "ec2" in services and bool(services.intersection(DATABASE_ENGINE_SERVICES))


def string_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    if isinstance(value, tuple):
        return tuple(str(item) for item in value)
    return ()


def first_known(*values: str | None) -> str:
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized.lower() != "unknown":
            return normalized
    return ""


def contains_manual_pattern(value: str) -> bool:
    # Keyword heuristic used by add_business_context_evidence() to decide
    # whether a free-text lifecycle answer describes manual onboarding
    # (-> TLO-02 "missing") versus an automated one (-> "partial"). Kept
    # narrow and literal on purpose - a false negative here just falls
    # through to "partial" rather than mis-scoring an automated process as
    # broken.
    lowered = value.lower()
    return any(term in lowered for term in ("manual", "spreadsheet", "ticket", "email", "engineer"))


def normalize_status(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized in {"na", "n_a", "notapplicable"}:
        normalized = "not_applicable"
    return normalized if normalized in VALID_STATUSES else "unknown"


def normalize_confidence(value: Any) -> str:
    normalized = str(value or "low").strip().lower()
    return normalized if normalized in VALID_CONFIDENCE else "low"


def normalize_evidence_state(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    return normalized if normalized in VALID_EVIDENCE_STATES else "unknown"


def set_if_absent(evidence_by_control: dict[str, Evidence], evidence: Evidence) -> None:
    if evidence.control_id not in evidence_by_control:
        evidence_by_control[evidence.control_id] = evidence


def score_at_or_below(
    dimensions: dict[str, DimensionResult],
    dimension_ids: tuple[str, ...],
    threshold: float,
) -> bool:
    # Shared by apply_maturity_gates() and routing_recommendations(): "any
    # one of these dimensions is weak" rather than "all of them" - a gate or
    # routing rule should trigger even if only tenant isolation (not tenant
    # lifecycle) is weak, since either alone is a real risk on its own.
    for dimension_id in dimension_ids:
        dimension = dimensions.get(dimension_id)
        if dimension and dimension.score is not None and dimension.score <= threshold:
            return True
    return False


def priority_sort_value(priority: str, status: str) -> int:
    """Turn (priority, status) into a single ascending sort key.

    priority_rank dominates (10-point gaps between high/medium/low) so a
    high-priority "partial" always sorts before a medium-priority "missing".
    status_rank is only a tiebreaker within the same priority tier, ordered
    missing < partial < unknown because a confirmed gap is more actionable
    than an unresolved unknown.
    """

    priority_rank = {"high": 0, "medium": 10, "low": 20}.get(priority, 30)
    status_rank = {"missing": 0, "partial": 1, "unknown": 2}.get(status, 3)
    return priority_rank + status_rank


def plain_language_summary(result: AssessmentResult) -> str:
    weak_dimensions = [
        dimension.name
        for dimension in result.dimensions
        if dimension.score is not None and dimension.score <= 2
    ]
    if not weak_dimensions:
        return (
            "Available evidence does not show a scored dimension at or below 2 / 5. "
            "Review coverage and confidence before treating this as a final maturity view."
        )
    return (
        "The evidence currently highlights these areas for priority attention: "
        f"{', '.join(weak_dimensions)}."
    )


def score_explanation(result: AssessmentResult) -> str:
    if result.overall_score is None:
        return "The assessment could not calculate a maturity score because no scoreable evidence was supplied."
    return (
        f"The overall score is {result.overall_score:g} / 5. Confidence is {result.overall_confidence}. "
        "Unknown evidence is not counted as zero, but it lowers confidence. Missing capabilities "
        "count as zero. Maturity gates cap the overall score when foundational SaaS controls are weak."
    )


def format_score(score: float | None) -> str:
    if score is None:
        return "not scored"
    formatted = f"{score:.2f}".rstrip("0").rstrip(".")
    return f"{formatted} / 5"


def maturity_label(score: float | None) -> str:
    if score is None:
        return "No scoreable evidence"
    rounded = max(0, min(5, round(score)))
    return MATURITY_SCALE.get(rounded, "Unknown")


def limit_gaps(gaps: tuple[str, ...]) -> tuple[str, ...]:
    if not gaps:
        return ("None from the supplied evidence.",)
    if len(gaps) <= 20:
        return gaps
    return gaps[:20] + (f"plus {len(gaps) - 20} more gaps",)


def status_class(status: str) -> str:
    return f"status-{normalize_status(status)}"


def scope_disclaimer(scope: Scope) -> str:
    if scope.scope_type == "single-account":
        return (
            "Single-account assessment: tenancy model, centralized cost attribution, "
            "organization structure, and cross-account fleet operations may have limited "
            "confidence without org-level access."
        )
    return "Assessment scope should be reviewed with the customer before sharing results."


def to_plain(value: Any) -> Any:
    if is_dataclass(value):
        return {key: to_plain(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    return value


def display_path(path: Path, base_dir: Path) -> str:
    try:
        return str(path.relative_to(base_dir.resolve()))
    except ValueError:
        return str(path)


def escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


if __name__ == "__main__":
    raise SystemExit(main())
