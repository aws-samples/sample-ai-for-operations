# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: compute_urgency.

Deterministically derives an urgency tier from a deadline date and the current
date using configurable day thresholds. The language model NEVER produces this
value.

Urgency tiers (R5.2, default thresholds 7/30/90 days):
  critical  — deadline within 7 days, or classification is SERVICE_DISRUPTION
  high      — deadline within 30 days
  medium    — deadline within 90 days
  low       — deadline > 90 days away, or no deadline, or INFORMATIONAL / UNCLASSIFIED
"""

from __future__ import annotations

from datetime import date, datetime, timezone

# Tier labels
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Classifications that always get urgency LOW regardless of deadline (R5.3)
_ALWAYS_LOW = {"INFORMATIONAL", "UNCLASSIFIED"}

# Classification that always gets CRITICAL regardless of deadline
_ALWAYS_CRITICAL = {"SERVICE_DISRUPTION"}

# Default day thresholds (R5.2)
DEFAULT_THRESHOLDS = {"critical_days": 7, "high_days": 30, "medium_days": 90}


def compute_urgency(
    deadline: str | None,
    classification: str,
    now: date | None = None,
    thresholds: dict | None = None,
) -> str:
    """Compute urgency tier deterministically.

    Args:
        deadline: ISO 8601 date string (YYYY-MM-DD) or None.
        classification: The event classification string.
        now: The reference date for comparison (defaults to UTC today).
        thresholds: Dict with keys critical_days, high_days, medium_days.
                    Defaults to 7/30/90.

    Returns:
        One of: "critical", "high", "medium", "low".
    """
    # Always LOW for these classifications (R5.3)
    if classification in _ALWAYS_LOW:
        return LOW

    # Always CRITICAL for active disruptions (no deadline needed)
    if classification in _ALWAYS_CRITICAL:
        return CRITICAL

    if not deadline:
        return LOW

    t = thresholds or DEFAULT_THRESHOLDS
    critical_days = int(t.get("critical_days", 7))
    high_days = int(t.get("high_days", 30))
    medium_days = int(t.get("medium_days", 90))

    ref = now or datetime.now(timezone.utc).date()
    try:
        if isinstance(deadline, str):
            dl = date.fromisoformat(deadline[:10])
        else:
            dl = deadline
    except ValueError:
        return LOW

    delta = (dl - ref).days

    if delta < 0:
        # Past deadline — treat as critical
        return CRITICAL
    if delta <= critical_days:
        return CRITICAL
    if delta <= high_days:
        return HIGH
    if delta <= medium_days:
        return MEDIUM
    return LOW
