# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: summarize_investigation_outcome.

Parses the AWS DevOps Agent's markdown analysis (produced by the skill at
devops-agent-skill/SKILL.md) into a structured outcome and maps it onto
this agent's own `impact` enum (R12.7). Pure code — no model call. The LLM
already produced the analysis text inside the DevOps Agent investigation;
this function only extracts structure from it deterministically, the same
role the reference's parseAgentAnalysis()/buildOutput() play.

Heading contract (must match devops-agent-skill/SKILL.md exactly):
  ## Summary
  ## Key Findings
  ## Answers to Your Questions
  ## Recommended Actions
  ## Notification Routing
  ## Jira Tracking   (shipped skill omits this section — see requirements.md)
"""

from __future__ import annotations

import re

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "MINIMAL": 0}
_VALID_SEVERITIES = set(_SEVERITY_RANK)

_NO_IMPACT_INDICATORS = (
    "no workloads",
    "no operational impact",
    "no current operational impact",
    "not used by any",
    "no immediate operational",
)
_HAS_IMPACT_INDICATORS = (
    "will be unavailable",
    "service disruption",
    "degradation expected",
    "instances will be stopped",
    "blast radius",
    "affected workloads",
)

_PRIORITY_LABEL_MAP = {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM", "P4": "LOW"}

_SUMMARY_RE = re.compile(r"## Summary\s*\n+([\s\S]*?)(?=\n##|\n---|\n\|)")
_FINDINGS_SECTION_RE = re.compile(r"## Key Findings([\s\S]*?)(?=\n## (?!Key)|\n---)")
_ANSWERS_SECTION_RE = re.compile(r"## Answers to Your Questions([\s\S]*?)$")
_BULLET_RE = re.compile(r"[-•*]\s+\*\*(.+?)\*\*[:\s]*(.*)")
_RECS_SECTION_RE = re.compile(
    r"(?:### 4\.|## (?:Recommended )?Actions|What actions)([\s\S]*?)"
    r"(?=\n## (?!Rec)|\n---|\*\*No immediate)"
)
_TABLE_ROW_RE = re.compile(r"\|\s*\*\*(P\d+)\*\*\s*\|\s*(.+?)\s*\|")
_NUMBERED_RE = re.compile(r"\d+\.\s+(.+)")
_SEVERITY_LEADING_RE = re.compile(
    r"^[*_\s]*(CRITICAL|HIGH|MEDIUM|LOW|MINIMAL)\b", re.IGNORECASE
)


def _parse_severity(text: str) -> str | None:
    """Extracts a leading severity word from a finding bullet's detail."""
    match = _SEVERITY_LEADING_RE.match(text.strip())
    return match.group(1).upper() if match else None


def _map_priority_label(label: str) -> str:
    return _PRIORITY_LABEL_MAP.get(label, "MEDIUM")


def _highest_severity(severities: list[str]) -> str | None:
    best: str | None = None
    for severity in severities:
        if best is None or _SEVERITY_RANK.get(severity, -1) > _SEVERITY_RANK.get(best, -1):
            best = severity
    return best


def _parse_agent_analysis(analysis: str, fallback_priority: str) -> dict:
    result = {
        "has_impact": False,
        "summary": "",
        "root_cause": None,
        "overall_severity": None,
        "findings": [],
        "recommendations": [],
    }

    summary_match = _SUMMARY_RE.search(analysis)
    if summary_match:
        result["summary"] = summary_match.group(1).strip().replace("\n", " ")[:500]
    else:
        paragraphs = analysis.split("\n\n")
        first = next((p for p in paragraphs if len(p) > 50 and not p.startswith("#")), None)
        result["summary"] = (first.strip().replace("\n", " ")[:500] if first else "Investigation completed")

    findings_section = _FINDINGS_SECTION_RE.search(analysis)
    answers_section = _ANSWERS_SECTION_RE.search(analysis)
    content_to_search = (
        findings_section.group(1) if findings_section
        else answers_section.group(1) if answers_section
        else analysis
    )

    all_finding_severities: list[str] = []
    bullets = _BULLET_RE.findall(content_to_search)
    for index, (title, detail) in enumerate(bullets):
        severity = _parse_severity(detail) or fallback_priority
        all_finding_severities.append(severity)
        if index < 5:
            result["findings"].append(
                {
                    "description": f"{title}: {detail}".strip(),
                    "severity": severity,
                    "affectedResources": [],
                }
            )

    recs_section = _RECS_SECTION_RE.search(analysis)
    if recs_section:
        recs_text = recs_section.group(1)
        table_rows = _TABLE_ROW_RE.findall(recs_text)
        if table_rows:
            for priority_label, description in table_rows:
                result["recommendations"].append(
                    {"description": description.strip(), "priority": _map_priority_label(priority_label)}
                )
        else:
            for item in _NUMBERED_RE.findall(recs_text)[:5]:
                result["recommendations"].append({"description": item.strip(), "priority": "MEDIUM"})

    lower_analysis = analysis.lower()
    no_impact_score = sum(1 for i in _NO_IMPACT_INDICATORS if i in lower_analysis)
    has_impact_score = sum(1 for i in _HAS_IMPACT_INDICATORS if i in lower_analysis)

    if result["recommendations"] or result["findings"]:
        result["has_impact"] = True
    if no_impact_score > has_impact_score and no_impact_score >= 2:
        result["has_impact"] = bool(result["recommendations"])

    if not result["findings"] and result["has_impact"]:
        result["findings"].append(
            {"description": result["summary"][:200], "severity": fallback_priority, "affectedResources": []}
        )
        all_finding_severities.append(fallback_priority)

    result["overall_severity"] = _highest_severity(all_finding_severities)
    return result


def summarize_investigation_outcome(
    analysis_markdown: str | None,
    fallback_priority: str,
) -> dict:
    """Summarizes an AWS DevOps Agent investigation's markdown analysis.

    Args:
        analysis_markdown: The agent's last assistant journal message text,
            or None if the investigation completed but no analysis could be
            retrieved (degraded case — still surfaces for human review, see
            below).
        fallback_priority: The intake-time priority (from
            build_webhook_payload's category mapping) used when the agent's
            analysis carries no parseable severity word.

    Returns:
        {"impact": "confirmed"|"not_detected"|"unverifiable",
         "summary": str, "root_cause": str | None, "severity": str,
         "findings": list[dict], "recommendations": list[dict],
         "investigation_status": "IMPACT_DETECTED"|"NO_IMPACT"}
    """
    fallback_priority = fallback_priority if fallback_priority in _VALID_SEVERITIES else "MEDIUM"

    if not analysis_markdown:
        # Degraded case: investigation completed but analysis could not be
        # retrieved. Intentionally NOT downgraded to unverifiable-and-hidden —
        # the fallback priority is kept so the ticket still surfaces for a
        # human to review, matching the reference's explicit choice.
        return {
            "impact": "unverifiable",
            "summary": "Investigation completed but no analysis available",
            "root_cause": None,
            "severity": fallback_priority,
            "findings": [],
            "recommendations": [],
            "investigation_status": "NO_IMPACT",
        }

    parsed = _parse_agent_analysis(analysis_markdown, fallback_priority)

    severity = (
        (parsed["overall_severity"] or fallback_priority) if parsed["has_impact"] else "LOW"
    )
    impact = "confirmed" if parsed["has_impact"] else "not_detected"

    return {
        "impact": impact,
        "summary": parsed["summary"],
        "root_cause": parsed["root_cause"],
        "severity": severity,
        "findings": parsed["findings"],
        "recommendations": parsed["recommendations"],
        "investigation_status": "IMPACT_DETECTED" if parsed["has_impact"] else "NO_IMPACT",
    }
