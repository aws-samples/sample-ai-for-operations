# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`evaluate`, `diff` and `report` (design.md D§2.1, tasks.md 1.22-1.26)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from config import load_settings
from drift_core import diff as diff_core
from drift_core import report as report_core
from drift_core.artifacts import ArtifactError, Artifacts
from drift_core.collectors.errors import describe
from drift_core.evaluate import evaluate
from drift_core.logging_util import get_logger, log_event
from drift_core.run_info import InputError
from drift_core.state_store import StateStore
from handlers import aws_clients

METRIC_NAMESPACE = "NetworkRoutingDriftChecker"
_REASON_MAX = 200


def _artifacts(event: dict[str, Any]) -> Artifacts:
    run_id = event.get("run_id") if isinstance(event, dict) else None
    if not run_id or not isinstance(run_id, str):
        raise InputError("run_id is required")
    return Artifacts(aws_clients.client("s3"), load_settings().require("bucket_name"), run_id)


def _reason(result: dict[str, Any]) -> str:
    text = describe(str(result.get("reason") or result.get("status") or "unknown error"))
    return text[:_REASON_MAX]


def evaluate_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Event: {run_id, cloudwan: {status, reason?} | null, regions: [{region, status, reason?}]}."""
    log = get_logger("evaluate", load_settings().log_level)
    artifacts = _artifacts(event)
    manifest = artifacts.get_json("manifest.json")

    cloudwan_snapshot, cloudwan_error = None, None
    cw_result = event.get("cloudwan") or {}
    cw_status = cw_result.get("status", "skipped")
    if cw_status == "ok":
        cloudwan_snapshot = artifacts.get_json("cloudwan.json")
    elif cw_status not in ("absent", "skipped"):
        cloudwan_error = _reason(cw_result)

    regions: dict[str, dict[str, Any]] = {}
    not_evaluated: dict[str, str] = {}
    results = {r.get("region"): r for r in event.get("regions") or [] if isinstance(r, dict)}
    for region in manifest["regions"]["evaluate"]:
        result = results.get(region)
        if result is None:
            not_evaluated[region] = "no collection result"
        elif result.get("status") == "ok":
            regions[region] = artifacts.get_json(f"regions/{region}.json")
        else:
            not_evaluated[region] = _reason(result)

    result = evaluate(cloudwan_snapshot, regions, manifest, not_evaluated, cloudwan_error)
    payload = {**result.to_dict(), "cloudwan_evaluated": cloudwan_snapshot is not None or cw_status == "absent"}
    artifacts.put_json("findings.json", payload)
    severities: dict[str, int] = {}
    for f in result.findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
    log_event(log, "evaluated", run_id=artifacts.run_id, findings=severities,
              regions_not_evaluated=sorted(not_evaluated))
    return {"run_id": artifacts.run_id, "findings": severities}


def diff_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    settings = load_settings()
    log = get_logger("diff", settings.log_level)
    artifacts = _artifacts(event)
    evaluation = artifacts.get_json("findings.json")
    sources = set(evaluation.get("regions_evaluated") or []) | {"global"}
    if evaluation.get("cloudwan_evaluated"):
        sources.add("cloudwan")
    store = StateStore(aws_clients.table(settings.require("table_name")))
    # Run time, not wall-clock time: ages and first/last-seen are measured between runs, and a
    # re-driven execution records the same timestamps as the original.
    now = artifacts.get_json("manifest.json")["started_at"]
    result = diff_core.compute(evaluation.get("findings") or [], store.load_open(), sources, now, artifacts.run_id)
    store.write_items(result.writes)
    artifacts.put_json("diff.json", result.to_dict())
    drift = result.counts("drift")
    store.put_run(artifacts.run_id, {"finished_diff": now, "counts": result.counts(), "drift_counts": drift,
                                     "regions_evaluated": sorted(evaluation.get("regions_evaluated") or []),
                                     "regions_not_evaluated": sorted(evaluation.get("regions_not_evaluated") or {})},
                  now)
    log_event(log, "diffed", run_id=artifacts.run_id, counts=result.counts(), drift=drift)
    return {"run_id": artifacts.run_id, "new_drift": drift["new"], "known_drift": drift["known"],
            "resolved_drift": drift["resolved"]}


def report_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """Returns {subject, body, scope, started_at}; the state machine publishes it to SNS."""
    log = get_logger("report", load_settings().log_level)
    artifacts = _artifacts(event)
    manifest = artifacts.get_json("manifest.json")
    evaluation = artifacts.get_json("findings.json")
    diff = artifacts.get_json("diff.json")
    # The state machine always passes `investigation`: the MergeInvestigations summary when the
    # hand-off ran, or {"status": "skipped"} when it did not (no NEW findings, hand-off off).
    investigation = event.get("investigation")
    if not isinstance(investigation, dict) or investigation.get("status") == "skipped":
        investigation = None
    else:
        # The state carries only Merge's compact summary; the incidents are in investigation.json.
        # If that can't be read, the report still goes out and says the investigation failed.
        try:
            investigation = artifacts.get_json("investigation.json")
        except (ArtifactError, ValueError):
            investigation = {"batches": [{"batch_n": b.get("batch_n"), "status": "failed:result unreadable"}
                                         for b in investigation.get("batches") or [{"batch_n": 1}]],
                             "incidents": []}
    rep = report_core.compose(
        date=manifest["started_at"][:10], run_id=artifacts.run_id, evaluation=evaluation, diff=diff,
        findings_uri=artifacts.uri("findings.json"), handoff_enabled=bool(manifest.get("handoff_enabled")),
        investigation=investigation)
    artifacts.put_text("report.txt", rep.body)

    now = dt.datetime.now(dt.UTC)
    started = dt.datetime.fromisoformat(manifest["started_at"].replace("Z", "+00:00"))
    drift = diff.get("drift_counts") or {}
    print(report_core.emf_metrics(METRIC_NAMESPACE, {  # noqa: T201 - EMF must be a raw stdout line
        "FindingsNew": drift.get("new", 0), "FindingsKnown": drift.get("known", 0),
        "FindingsResolved": drift.get("resolved", 0),
        "RegionsNotEvaluated": len(evaluation.get("regions_not_evaluated") or {}),
        "RunDurationSeconds": round((now - started).total_seconds(), 1),
    }, int(now.timestamp() * 1000)))
    # The lookback marker may only advance past a run that evaluated everything. Otherwise drift
    # in a Region that failed today would get a lookback window starting after the failure.
    complete = (not evaluation.get("regions_not_evaluated") and bool(evaluation.get("cloudwan_evaluated"))
                and (manifest.get("dx_gateways") or {}).get("status", "ok") == "ok")
    advance_marker = manifest["scope"] == "full" and complete
    log_event(log, "reported", run_id=artifacts.run_id, kind=rep.kind, complete=complete,
              advance_marker=advance_marker)
    return {"subject": rep.subject, "body": rep.body, "kind": rep.kind, "scope": manifest["scope"],
            "started_at": manifest["started_at"], "complete": complete, "advance_marker": advance_marker}
