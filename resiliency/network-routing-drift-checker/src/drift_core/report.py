# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Compose the SNS message (requirements §10.2). Precision code: run artifacts -> text.

Clean run  -> heartbeat: one summary line, plus one line per item that was NOT verified
              (Region / Cloud WAN not evaluated, truncated table, intent rejected), so a
              partial evaluation can never read as clean.
Drift run  -> drift report: summary, NEW in full, KNOWN with age, RESOLVED, notes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

NO_HANDOFF = "No investigation was performed: DevOps Agent hand-off is not enabled."
NO_NEW = "No investigation was performed: there are no new drift findings since the last run."
SUBJECT_MAX = 100
BODY_MAX_BYTES = 120_000  # leaves headroom under the 256 KB Step Functions state and SNS message limits
TOTAL_CHECKS = 6


@dataclass(frozen=True)
class Report:
    kind: str  # "heartbeat" | "drift"
    subject: str
    body: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "subject": self.subject, "body": self.body}


def _summary_line(date: str, evaluation: dict[str, Any]) -> str:
    # "check2-tgw" is the TGW half of check 2, not a seventh check.
    run = len({c.split("-")[0] for c in evaluation.get("checks_run") or []})
    skipped = len(evaluation.get("checks_skipped") or [])
    reason = evaluation.get("skip_reason")
    parts = [f"{run} of {TOTAL_CHECKS} checks run", f"{evaluation.get('resources_evaluated', 0)} resources evaluated"]
    if skipped:
        parts.append(f"{skipped} checks skipped" + (f" ({reason})" if reason else ""))
    not_eval = evaluation.get("regions_not_evaluated") or {}
    if not_eval:
        parts.append("Regions not evaluated: " + ", ".join(sorted(not_eval)))
    return f"{date}: " + ", ".join(parts) + "."


def _line(entry: dict[str, Any], with_age: bool = False) -> str:
    text = f"- [{entry.get('kind')}] {entry.get('region')}: {entry.get('message')} (id {entry.get('finding_id')})"
    if with_age:
        age = entry.get("age_days", 0)
        extras = [f"first seen {str(entry.get('first_seen', ''))[:10]} ({age} day{'' if age == 1 else 's'})"]
        if entry.get("changed"):
            extras.append("changed since last run")
        if entry.get("unverified"):
            extras.append("not re-verified this run: its source was not evaluated")
        text += " - " + "; ".join(extras)
    return text


def _section(title: str, entries: list[dict[str, Any]], with_age: bool = False) -> list[str]:
    if not entries:
        return []
    return ["", f"{title} ({len(entries)})", *[_line(e, with_age) for e in entries]]


def _by(entries: list[dict[str, Any]], severity: str) -> list[dict[str, Any]]:
    return [e for e in entries if e.get("severity") == severity]


def _cap(lines: list[str], findings_uri: str) -> str:
    body = "\n".join(lines)
    if len(body.encode("utf-8")) <= BODY_MAX_BYTES:
        return body
    kept: list[str] = []
    size = 0
    for line in lines:
        size += len(line.encode("utf-8")) + 1
        if size > BODY_MAX_BYTES - 500:
            break
        kept.append(line)
    omitted = len(lines) - len(kept)
    kept += ["", f"... message truncated: {omitted} more lines. Full findings: {findings_uri}"]
    return "\n".join(kept)


def _evidence_text(item: dict[str, Any]) -> str:
    kind = item.get("type")
    if kind == "cloudtrail":
        parts = [f"CloudTrail {item.get('event_name') or 'event'} {item.get('event_id')}"]
        if item.get("time"):
            parts.append(f"at {item['time']}")
        if item.get("actor"):
            parts.append(f"by {item['actor']}")
        return " ".join(parts)
    if kind == "health":
        return f"AWS Health {item.get('event_arn')}"
    return f"observed {item.get('resource')}: {item.get('observation')}"


HYPOTHESIS_MAX = 400  # the full text stays in investigation.json and in DevOps Agent
_DURATION = re.compile(r"^P(?:(\d+)W)?(?:(\d+)D)?$")


def _duration(value: Any) -> str:
    """ISO-8601 'P3D' / 'P2W' -> '3 days' / '14 days'; anything else is shown as given."""
    match = _DURATION.match(str(value or ""))
    if not match or not any(match.groups()):
        return str(value)
    days = int(match.group(1) or 0) * 7 + int(match.group(2) or 0)
    return f"{days} day{'' if days == 1 else 's'}"


def _short(text: Any, has_link: bool) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= HYPOTHESIS_MAX:
        return text
    cut = text[:HYPOTHESIS_MAX].rsplit(" ", 1)[0]
    return cut + (" … (full text in the investigation)" if has_link else " …")


def _incident_lines(inc: dict[str, Any]) -> list[str]:
    blast = inc.get("blast_radius") or {}
    env = f", Environment={blast['environment']}" if blast.get("environment") else ""
    lines = [
        f"{inc.get('rank')}. {inc.get('title')}",
        # Explicit `+` so this reads as one list element, not three.
        f"   Confidence {inc.get('confidence')}; blast radius score {blast.get('score', 0)} "
        + f"({blast.get('prefixes', 0)} prefixes, {blast.get('attachments', 0)} attachments, "
        + f"{blast.get('domains', 0)} domains{env}); present for {_duration(inc.get('stable_for'))}.",
        f"   Findings: {', '.join(inc.get('member_finding_ids') or [])}",
        f"   Hypothesis: {_short(inc.get('root_cause_hypothesis'), bool(inc.get('investigation_url')))}",
        "   Actor: " + ("identified" if inc.get("actor_identified") else "not identified"),
    ]
    evidence = inc.get("evidence") or []
    lines.append("   Evidence:" if evidence else "   Evidence: none cited")
    lines += [f"     - {_evidence_text(e)}" for e in evidence]
    commands = inc.get("validation_commands") or []
    if commands:
        lines.append("   Verify (read-only):")
        lines += [f"     {c}" for c in commands]
    if inc.get("investigation_url"):
        lines.append(f"   Investigation: {inc['investigation_url']}")
    return lines


def _investigation_section(inv: dict[str, Any]) -> tuple[list[str], str]:
    """Lines for the INVESTIGATION section and a subject suffix (requirements §10.2)."""
    batches = inv.get("batches") or []
    failed = [b for b in batches if not str(b.get("status", "")).startswith("ok")]
    incidents = inv.get("incidents") or []
    # Explicit `+` so this reads as two list elements ("" and the one sentence), not three.
    lines = ["", f"INVESTIGATION (AWS DevOps Agent): {len(incidents)} incident(s) from "
                 + f"{len(batches) - len(failed)} of {len(batches)} batch(es), ranked by blast radius"]
    for inc in incidents:
        lines += _incident_lines(inc)
    unassigned = sorted({fid for b in batches for fid in b.get("unassigned_finding_ids") or []})
    if unassigned:
        lines.append(f"Not explained by the investigation: {', '.join(unassigned)}")
    if len(failed) == len(batches):
        reasons = "; ".join(f"batch {b.get('batch_n')}: {str(b.get('status')).removeprefix('failed:')}"
                            for b in failed) or "no batch result"
        lines.append(f"Investigation failed: {reasons}. Raw findings follow.")
        suffix = " (investigation failed)"
    else:
        for b in failed:
            lines.append(f"Investigation batch {b.get('batch_n')} failed: "
                         f"{str(b.get('status')).removeprefix('failed:')}; its raw findings follow in NEW.")
        suffix = " (investigated)" if not failed else " (partly investigated)"
    for b in batches:
        if b.get("status") == "ok" and b.get("investigation_url") and not any(
                inc.get("investigation_url") == b["investigation_url"] for inc in incidents):
            lines.append(f"Investigation link (batch {b.get('batch_n')}): {b['investigation_url']}")
    invariant = inv.get("invariant") or {}
    if invariant and not invariant.get("ok", True):
        lines.append("Not verified: the investigation batches did not cover the NEW findings exactly "
                     f"(missing {invariant.get('missing') or []}, unexpected {invariant.get('unexpected') or []}, "
                     f"duplicated {invariant.get('duplicated') or []}). This is a checker bug; please report it.")
    return lines, suffix


def compose(*, date: str, run_id: str, evaluation: dict[str, Any], diff: dict[str, Any], findings_uri: str,
            handoff_enabled: bool = False, investigation: dict[str, Any] | None = None) -> Report:
    """Build the heartbeat or drift report for one run."""
    new, known, resolved = diff.get("new") or [], diff.get("known") or [], diff.get("resolved") or []
    drift_new, drift_known, drift_resolved = _by(new, "drift"), _by(known, "drift"), _by(resolved, "drift")
    system_now = _by(new, "system") + _by(known, "system")
    info_new, info_known = _by(new, "informational"), _by(known, "informational")
    summary = _summary_line(date, evaluation)

    if not (drift_new or drift_known or drift_resolved):
        lines = [f"Network routing drift check {summary.replace(': ', ': no drift. ', 1)}"]
        lines += [f"- {e.get('message')}" for e in system_now]
        if info_new or info_known:
            lines.append(f"- Informational: {len(info_new)} new, {len(info_known)} known (see {findings_uri}).")
        subject = f"Network routing drift check {date}: no drift"
        if system_now:
            subject += f" ({len(system_now)} not verified)"
        return Report("heartbeat", subject[:SUBJECT_MAX], _cap(lines, findings_uri))

    counts = f"{len(drift_new)} new, {len(drift_known)} known, {len(drift_resolved)} resolved"
    lines = [f"Network routing drift report {date} (run {run_id})", f"Drift findings: {counts}.", summary, ""]
    suffix = ""
    if investigation is None:
        lines.append(NO_HANDOFF if not handoff_enabled else NO_NEW)
    else:
        section, suffix = _investigation_section(investigation)
        lines += section
    lines += _section("NEW", drift_new)
    lines += _section("KNOWN", drift_known, with_age=True)
    lines += _section("RESOLVED", drift_resolved, with_age=True)
    lines += _section("NOT VERIFIED", system_now)
    resolved_other = _by(resolved, "system") + _by(resolved, "informational")
    if resolved_other:
        lines += ["", f"Also resolved: {len(resolved_other)} informational or not-verified item(s)."]
    lines += _section("INFORMATIONAL (new)", info_new)
    if info_known:
        lines += ["", f"Informational (known): {len(info_known)}."]
    lines += ["", f"Full findings: {findings_uri}"]
    subject = f"Network routing drift {date}: {counts}{suffix}"
    return Report("drift", subject[:SUBJECT_MAX], _cap(lines, findings_uri))


def emf_metrics(namespace: str, metrics: dict[str, float], timestamp_ms: int) -> str:
    """One CloudWatch Embedded Metric Format line (no PutMetricData permission needed)."""
    return json.dumps({
        "_aws": {"Timestamp": timestamp_ms, "CloudWatchMetrics": [{
            "Namespace": namespace, "Dimensions": [[]],
            "Metrics": [{"Name": name, "Unit": "Seconds" if name.endswith("Seconds") else "Count"}
                        for name in metrics]}]},
        **metrics,
    }, sort_keys=True)
