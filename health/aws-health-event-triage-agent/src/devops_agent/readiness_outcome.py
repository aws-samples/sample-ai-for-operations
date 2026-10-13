# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: summarize_readiness_outcome.

Parses the AWS DevOps Agent's readiness-assessment markdown (produced by
the skill at devops-agent-skill/readiness-assessment/SKILL.md) into a
structured outcome. Pure code — no model call. The LLM already produced
the analysis text inside the DevOps Agent investigation; this function
only extracts structure from it deterministically.

Contract (fixed heading + flat key-value lines, matching the confirmed
reference's "CDK Change Spec" block shape — see design.md §6):

  ## Readiness Assessment

  FEASIBILITY: READY | BLOCKED | NEEDS_REMEDIATION
  BLOCKERS: <comma-separated list, or NONE>
  RISK: LOW | MEDIUM | HIGH
  ROLLBACK_AVAILABLE: YES | NO

Never raises. Unrecognized/missing values degrade to "unverifiable"
(feasibility) / "unknown" (risk) rather than dropping the ticket, matching
the incident gate's degraded-case philosophy.
"""

from __future__ import annotations

import re

_SECTION_RE = re.compile(r"## Readiness Assessment\s*\n+([\s\S]*?)(?=\n##|\Z)")
_FEASIBILITY_RE = re.compile(r"^FEASIBILITY:\s*(\S+)", re.MULTILINE)
_BLOCKERS_RE = re.compile(r"^BLOCKERS:\s*(.+)$", re.MULTILINE)
_RISK_RE = re.compile(r"^RISK:\s*(\S+)", re.MULTILINE)
_ROLLBACK_RE = re.compile(r"^ROLLBACK_AVAILABLE:\s*(\S+)", re.MULTILINE)

_FEASIBILITY_MAP = {
    "READY": "ready",
    "BLOCKED": "blocked",
    "NEEDS_REMEDIATION": "needs_remediation",
}
_RISK_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


def summarize_readiness_outcome(analysis_markdown: str | None) -> dict:
    """Summarizes an AWS DevOps Agent readiness-assessment markdown.

    Args:
        analysis_markdown: The agent's last assistant journal message text,
            or None if the assessment completed but no analysis could be
            retrieved.

    Returns:
        {"feasibility": "ready"|"blocked"|"needs_remediation"|"unverifiable",
         "blockers": list[str], "risk": "low"|"medium"|"high"|"unknown",
         "rollback_available": bool | None, "summary": str}
    """
    if not analysis_markdown:
        return {
            "feasibility": "unverifiable",
            "blockers": [],
            "risk": "unknown",
            "rollback_available": None,
            "summary": "Readiness assessment completed but no analysis available",
        }

    section_match = _SECTION_RE.search(analysis_markdown)
    content = section_match.group(1) if section_match else analysis_markdown

    feasibility_match = _FEASIBILITY_RE.search(content)
    feasibility_raw = feasibility_match.group(1).upper() if feasibility_match else ""
    feasibility = _FEASIBILITY_MAP.get(feasibility_raw, "unverifiable")

    blockers_match = _BLOCKERS_RE.search(content)
    blockers_raw = blockers_match.group(1).strip() if blockers_match else "NONE"
    if blockers_raw.upper() == "NONE" or not blockers_raw:
        blockers: list[str] = []
    else:
        blockers = [b.strip() for b in blockers_raw.split(",") if b.strip()]

    risk_match = _RISK_RE.search(content)
    risk_raw = risk_match.group(1).upper() if risk_match else ""
    risk = _RISK_MAP.get(risk_raw, "unknown")

    rollback_match = _ROLLBACK_RE.search(content)
    rollback_raw = rollback_match.group(1).upper() if rollback_match else ""
    if rollback_raw == "YES":
        rollback_available: bool | None = True
    elif rollback_raw == "NO":
        rollback_available = False
    else:
        rollback_available = None

    summary_lines = [
        line.strip()
        for line in content.split("\n")
        if line.strip() and not re.match(r"^[A-Z_]+:", line.strip())
    ]
    summary = " ".join(summary_lines)[:500] if summary_lines else "Readiness assessment completed"

    return {
        "feasibility": feasibility,
        "blockers": blockers,
        "risk": risk,
        "rollback_available": rollback_available,
        "summary": summary,
    }
