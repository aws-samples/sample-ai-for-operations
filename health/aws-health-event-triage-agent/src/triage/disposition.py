# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: decide_disposition.

Deterministically derives a disposition (TICKET or DIGEST) for a health event
from the classification and per-eventTypeCode override rules. Pure code — no
model call.

Default rules (R6.2):
  TICKET  — SERVICE_DISRUPTION, BREAKING_CHANGE, SECURITY_RELATED, COST_IMPLICATION, UNCLASSIFIED
  DIGEST  — INFORMATIONAL

Per-code overrides are loaded from config/dispositions.json (or the path in
DISPOSITION_OVERRIDES_PATH). They take precedence over the class default.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

TICKET = "TICKET"
DIGEST = "DIGEST"

# Default per-classification disposition
_CLASS_DEFAULTS: dict[str, str] = {
    "SERVICE_DISRUPTION": TICKET,
    "BREAKING_CHANGE": TICKET,
    "SECURITY_RELATED": TICKET,
    "COST_IMPLICATION": TICKET,
    "INFORMATIONAL": DIGEST,
    "UNCLASSIFIED": TICKET,
}

_DEFAULT_OVERRIDES_PATH = Path(__file__).parents[2] / "config" / "dispositions.json"

_overrides_cache: dict[str, dict] | None = None


def _load_overrides() -> dict[str, dict]:
    global _overrides_cache
    if _overrides_cache is not None:
        return _overrides_cache
    path = Path(os.environ.get("DISPOSITION_OVERRIDES_PATH", str(_DEFAULT_OVERRIDES_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            _overrides_cache = {item["eventTypeCode"]: item for item in data if "eventTypeCode" in item}
        else:
            _overrides_cache = data
        logger.info("Loaded %d disposition overrides from %s", len(_overrides_cache), path)
    except FileNotFoundError:
        _overrides_cache = {}
    except Exception as exc:
        logger.warning("Could not load disposition overrides from %s: %s", path, exc)
        _overrides_cache = {}
    return _overrides_cache


def decide_disposition(
    classification: str,
    event_type_code: str,
    overrides: dict | None = None,
) -> dict:
    """Decide TICKET or DIGEST for an event.

    Args:
        classification: The classification string (e.g. "BREAKING_CHANGE").
        event_type_code: AWS Health eventTypeCode (e.g. "AWS_EKS_PLANNED_LIFECYCLE_EVENT").
        overrides: Optional dict of eventTypeCode → override entry. If None, loads from
                   config/dispositions.json.

    Returns:
        Dict with keys:
          - disposition: "TICKET" or "DIGEST"
          - precheck: precheck name to run, or None
          - rule: "class_default" | "code_override" | "fallback"
          - note: explanation string
    """
    loaded = overrides if overrides is not None else _load_overrides()
    override = loaded.get(event_type_code)

    if override:
        return {
            "disposition": override.get("disposition", TICKET),
            "precheck": override.get("precheck"),
            "rule": "code_override",
            "note": override.get("note", f"Per-code override for {event_type_code}"),
        }

    class_default = _CLASS_DEFAULTS.get(classification)
    if class_default:
        return {
            "disposition": class_default,
            "precheck": None,
            "rule": "class_default",
            "note": f"Class default for {classification}",
        }

    return {
        "disposition": TICKET,
        "precheck": None,
        "rule": "fallback",
        "note": f"Unknown classification '{classification}' — defaulting to TICKET",
    }


# ---------------------------------------------------------------------------
# Phase 4: escalate_on_precheck_failure (R6.4)
#
# A DIGEST event with a bound precheck that returns 'fail' is escalated to
# TICKET, naming the failing resources. 'pass' and 'not_checked' leave the
# disposition unchanged — a not_checked result stays in the digest with its
# reason visible (R7.4), it is never treated as a failure.
# ---------------------------------------------------------------------------

def escalate_on_precheck_failure(disposition_result: dict, precheck_result: dict) -> dict:
    """Escalate DIGEST to TICKET when the bound precheck fails.

    Args:
        disposition_result: The dict returned by decide_disposition().
        precheck_result: The PrecheckResult dict from run_precheck()
            (result: "pass" | "fail" | "not_checked").

    Returns:
        A new disposition dict. When escalated, adds 'escalated: True',
        'escalation_reason', and carries the precheck's failing_resources
        forward. Otherwise returns disposition_result unchanged (with
        'escalated: False' added for a consistent shape).
    """
    if disposition_result.get("disposition") != DIGEST:
        return {**disposition_result, "escalated": False}

    if precheck_result.get("result") != "fail":
        return {**disposition_result, "escalated": False}

    failing = precheck_result.get("failing_resources", [])
    resource_names = ", ".join(f["resource"] for f in failing) if failing else "unspecified resources"

    return {
        **disposition_result,
        "disposition": TICKET,
        "escalated": True,
        "escalation_reason": (
            f"Precheck '{precheck_result.get('precheck')}' failed for {resource_names} — " +
            "escalated from DIGEST to TICKET."
        ),
        "failing_resources": failing,
    }
