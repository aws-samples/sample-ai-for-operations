# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""NEW / KNOWN / RESOLVED against the drift-state history (requirements §8, design.md D§5.1).

Precision code: takes today's findings and the stored open items, returns the classification
and the items to write. The caller does the I/O.

RESOLVED requires that the finding's *source* was evaluated this run. A finding whose source
(its Region, or Cloud WAN) was not evaluated stays KNOWN and is marked `unverified`, so a
throttled Region can never "resolve" its findings.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

RESOLVED_TTL_DAYS = 90
SEVERITY_ORDER = {"drift": 0, "system": 1, "informational": 2}


def source_of(finding: dict[str, Any]) -> str:
    """Which collection a finding depends on: 'cloudwan' or its Region ('global' for run-level)."""
    if "core_network_id" in (finding.get("context") or {}):
        return "cloudwan"
    return finding.get("region") or "global"


def _parse(ts: str) -> dt.datetime:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))


def age_days(first_seen: str, now: str) -> int:
    return max(0, (_parse(now).date() - _parse(first_seen).date()).days)


@dataclass
class DiffResult:
    new: list[dict[str, Any]] = field(default_factory=list)
    known: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)  # full DynamoDB items to put

    def counts(self, severity: str | None = None) -> dict[str, int]:
        def n(items: list[dict[str, Any]]) -> int:
            return sum(1 for i in items if severity is None or i.get("severity") == severity)

        return {"new": n(self.new), "known": n(self.known), "resolved": n(self.resolved)}

    def to_dict(self) -> dict[str, Any]:
        return {"new": self.new, "known": self.known, "resolved": self.resolved,
                "counts": self.counts(), "drift_counts": self.counts("drift")}


def _sort_key(entry: dict[str, Any]) -> tuple:
    return (SEVERITY_ORDER.get(entry.get("severity", ""), 9), entry.get("check", ""), entry.get("kind", ""),
            entry.get("region", ""), entry.get("finding_id", ""))


def _item(finding: dict[str, Any], *, first_seen: str, now: str, run_id: str) -> dict[str, Any]:
    return {
        "pk": f"F#{finding['finding_id']}", "finding_id": finding["finding_id"], "status": "open",
        "check": finding["check"], "kind": finding["kind"], "severity": finding["severity"],
        "region": finding["region"], "source": source_of(finding), "message": finding.get("message", ""),
        "payload_hash": finding["payload_hash"], "first_seen": first_seen, "last_seen": now,
        "last_run_id": run_id,
    }


def compute(findings: list[dict[str, Any]], open_items: list[dict[str, Any]], evaluated_sources: set[str],
            now: str, run_id: str) -> DiffResult:
    """Classify today's findings against open history items."""
    result = DiffResult()
    open_by_id = {item["finding_id"]: item for item in open_items}
    seen: set[str] = set()
    for f in findings:
        fid = f["finding_id"]
        seen.add(fid)
        prior = open_by_id.get(fid)
        if prior is None:
            result.new.append({**f, "first_seen": now, "age_days": 0})
            result.writes.append(_item(f, first_seen=now, now=now, run_id=run_id))
            continue
        first_seen = prior.get("first_seen", now)
        result.known.append({**f, "first_seen": first_seen, "age_days": age_days(first_seen, now),
                             "changed": prior.get("payload_hash") != f["payload_hash"], "unverified": False})
        result.writes.append(_item(f, first_seen=first_seen, now=now, run_id=run_id))
    for fid, item in open_by_id.items():
        if fid in seen:
            continue
        base = {"finding_id": fid, "check": item.get("check"), "kind": item.get("kind"),
                "severity": item.get("severity"), "region": item.get("region"), "message": item.get("message", ""),
                "first_seen": item.get("first_seen", now)}
        if item.get("source", item.get("region", "global")) in evaluated_sources:
            result.resolved.append({**base, "age_days": age_days(base["first_seen"], now)})
            ttl = int((_parse(now) + dt.timedelta(days=RESOLVED_TTL_DAYS)).timestamp())
            result.writes.append({**item, "status": "resolved", "resolved_at": now, "ttl": ttl})
        else:
            result.known.append({**base, "age_days": age_days(base["first_seen"], now), "changed": False,
                                 "unverified": True, "last_seen": item.get("last_seen")})
    for bucket in (result.new, result.known, result.resolved):
        bucket.sort(key=_sort_key)
    return result
