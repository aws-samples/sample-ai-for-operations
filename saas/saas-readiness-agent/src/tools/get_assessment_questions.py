# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""Precision tool: return the prioritized, unanswered question bank."""

from __future__ import annotations

from typing import Any

from strands import tool

from src.assessment_core import Redactor, assess_payload
from src.questions import PHASES, QUESTIONS
from src.session_store import SessionStore
from src.tools._common import _merge_input_with_store, _parse_input_json

# Accepted question modes. "all" is kept as an alias of "full" for callers
# that used the older name; both return every unanswered topic.
QUESTION_MODES: dict[str, str] = {"essential": "essential", "full": "full", "all": "full"}

DIMENSION_NAMES: dict[str, str] = {
    "TAI": "Tenant Architecture & Isolation",
    "ITC": "Identity & Tenant Context",
    "TLO": "Tenant Lifecycle & Onboarding",
    "OOR": "Observability & Operational Readiness",
    "DPA": "Deployment & Platform Automation",
    "CAM": "Cost Attribution & Metering",
    "SBR": "Service Model & Business Readiness",
}


def _normalize_question_mode(mode: str) -> str:
    """Return the canonical mode, or raise ValueError for an unknown mode."""

    normalized = QUESTION_MODES.get(str(mode).strip().lower())
    if normalized is None:
        raise ValueError("mode must be 'essential' or 'full'.")
    return normalized


def _get_assessment_questions(input_json: str = "", mode: str = "essential") -> dict[str, Any]:
    """Return prioritized questions with metadata for the agent to present choices.

    This exists so the agent can tell the customer how many questions are
    available and what they cover BEFORE dumping a list. Counts come from the
    returned essential_count / extended_count, never from fixed numbers here.
    """

    mode = _normalize_question_mode(mode)

    payload: dict[str, Any] = _parse_input_json(input_json)
    redactor = Redactor()

    # Run a quick score pass (no AWS discovery) to identify which controls
    # are currently weak or unknown. Questions that resolve weak controls
    # get ranked higher — this is the "observe first, ask only what matters"
    # principle from the design notes.
    result = assess_payload(payload, redactor=redactor)

    # Exclude questions the customer already answered in a prior session or
    # earlier in this conversation, so we never repeat ourselves.
    # Check both PQ-* IDs and BQ-* scoring IDs (answers are stored as BQ-*).
    business_context = payload.get("business_context", {})
    answered_ids: set[str] = set()
    for answer in business_context.get("answers", []):
        qid = answer.get("question_id", "")
        if qid:
            answered_ids.add(qid)

    # Build the weak-control set: any control that scored unknown, missing,
    # or partial is a gap that a question might resolve.
    weak_controls = {
        control.id
        for dimension in result.dimensions
        for control in dimension.controls
        if control.status in {"unknown", "missing", "partial"}
    }

    # Separate questions into essential vs extended and compute relevance.
    essential_questions: list[dict[str, Any]] = []
    extended_questions: list[dict[str, Any]] = []

    for question in QUESTIONS:
        qid = str(question["id"])
        if qid in answered_ids:
            continue
        # Also skip if all of this question's scoring_ids have been answered
        scoring_ids = question.get("scoring_ids", {})
        if scoring_ids and all(sid in answered_ids for sid in scoring_ids):
            continue
        priority = str(question.get("priority", "extended"))
        controls = list(question.get("controls", []))
        relevance = sum(1 for c in controls if c in weak_controls)

        entry = {
            "id": qid,
            "phase": question.get("phase", 1),
            "persona": str(question.get("persona", "")),
            "prompt": str(question["prompt"]),
            "probes": list(question.get("probes", [])),
            "controls": controls,
            "scoring_ids": dict(question.get("scoring_ids", {})),
            "priority": priority,
            "relevance_score": relevance,
            "reasoning_hints": str(question.get("reasoning_hints", "")),
        }

        if priority == "essential":
            essential_questions.append(entry)
        else:
            extended_questions.append(entry)

    # Sort: by phase first (so questions flow naturally), then relevance
    # within each phase, then ID as stable tiebreaker.
    essential_questions.sort(key=lambda q: (q["phase"], -q["relevance_score"], q["id"]))
    extended_questions.sort(key=lambda q: (q["phase"], -q["relevance_score"], q["id"]))

    # "essential" returns only essential-priority topics; "full" adds the
    # extended topics (for example the conditional compliance topic).
    if mode == "essential":
        selected = essential_questions
    else:
        selected = essential_questions + extended_questions

    # Map which dimensions the selected questions touch, so the agent can
    # tell the customer "these cover Isolation, Identity, Lifecycle..." etc.
    dimensions_covered: set[str] = set()
    for q in selected:
        for control_id in q["controls"]:
            dim_prefix = control_id.split("-")[0] if "-" in control_id else control_id
            dimensions_covered.add(dim_prefix)

    dimensions_covered_names = sorted(DIMENSION_NAMES.get(d, d) for d in dimensions_covered)

    return {
        "total_available": len(essential_questions) + len(extended_questions),
        "essential_count": len(essential_questions),
        "extended_count": len(extended_questions),
        "dimensions_covered": dimensions_covered_names,
        "phases": PHASES,
        "questions": selected,
        "mode": mode,
        "note": (
            "Present questions ONE AT A TIME, phase by phase. "
            "Mention the persona when starting a new phase. "
            "After each phase, summarize what you heard before moving on. "
            "If the customer says 'skip' or 'enough', stop and proceed."
        ),
    }


@tool
def get_assessment_questions(
    input_json: str = "", mode: str = "essential"
) -> dict[str, Any]:
    """Return the prioritized question bank with metadata about available modes.

    Call this AFTER running discovery to see which questions would improve the
    assessment. The tool returns questions grouped by priority, with counts
    and dimension coverage, so the agent can present the customer with a
    choice of modes rather than dumping all questions at once.

    Args:
        input_json: Optional JSON string from a prior assessment run. If provided,
            already-answered questions are excluded and questions are ranked by
            how many weak/unknown controls they resolve.
        mode: "essential" (default): only unanswered topics marked essential.
            "full": every unanswered topic, essential plus extended. ("all" is
            accepted as an alias of "full".) Any other value is rejected. Use
            essential_count / extended_count from the result for the numbers;
            do not assume fixed counts.

    Returns:
        A dict with:
        - total_available: how many unanswered questions exist
        - essential_count: how many are marked "essential"
        - extended_count: how many are marked "extended"
        - dimensions_covered: which dimensions the selected questions touch
        - questions: the ordered list of questions for the chosen mode
        - mode: which mode was used
    """

    return _get_assessment_questions(input_json=input_json, mode=mode)


def make_session_tool(session_store: SessionStore) -> Any:
    """Return a variant of this tool that skips questions answered in session_store."""

    @tool
    def get_assessment_questions(
        input_json: str = "", mode: str = "essential"
    ) -> dict[str, Any]:
        """Precision tool: return only questions not resolved by saved answers."""

        merged = _merge_input_with_store(input_json, session_store)
        return _get_assessment_questions(merged, mode)

    return get_assessment_questions
