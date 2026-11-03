# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`BatchFindings`, `investigate` and `MergeInvestigations` (design.md D§3.2, D§3.3, D§6; tasks.md 3.1-3.3).

batch_handler   {run_id}                        -> {run_id, batch_count, batches: [{run_id, batch_n, batches}]}
handler         {run_id, batch: {batch_n}, task_token}  (Lambda .waitForTaskToken; ResultPath null)
merge_handler   {run_id, results: [Map iteration outputs]} -> compact per-batch summary

The HMAC secret is read from SSM SecureString at runtime, held only in a local variable, and
registered with the log redaction list together with the webhook URL and the task token. None of
them is ever logged, returned, or written to S3.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from config import load_settings
from drift_core import report as report_core
from drift_core.artifacts import Artifacts
from drift_core.cross_account import parse_function_arn
from drift_core.investigation import merge_investigations
from drift_core.logging_util import get_logger, log_event, register_secret
from drift_core.run_info import InputError
from drift_core.state_store import StateStore
from drift_core.webhook import (
    RunContext,
    WebhookConfigError,
    WebhookError,
    build_body,
    investigable,
    make_batches,
    post,
    signed_headers,
    timestamp,
    validate_url,
    webhook_region,
)
from handlers import aws_clients

BATCHES_ARTIFACT = "investigation-batches.json"
MERGED_ARTIFACT = "investigation.json"
METRIC_NAMESPACE = "NetworkRoutingDriftChecker"
# TOKEN# outlives the Step Functions wait by this much, so a late callback still finds (and
# discards) it, and MergeInvestigations can read started_at for a timed-out batch.
TOKEN_TTL_MARGIN_SECONDS = 900
_TIMEOUT_ERRORS = {"States.Timeout", "States.HeartbeatTimeout"}


def _artifacts(event: dict[str, Any]) -> Artifacts:
    run_id = event.get("run_id") if isinstance(event, dict) else None
    if not run_id or not isinstance(run_id, str):
        raise InputError("run_id is required")
    return Artifacts(aws_clients.client("s3"), load_settings().require("bucket_name"), run_id)


def _function_arn(context: Any) -> tuple[str, str, str]:
    try:
        return parse_function_arn(getattr(context, "invoked_function_arn", ""))
    except ValueError as exc:
        raise InputError("a Lambda context with invoked_function_arn is required") from exc


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _iso(moment: dt.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- BatchFindings -------------------------------------------------------------------------------

def batch_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    settings = load_settings()
    log = get_logger("batch", settings.log_level)
    artifacts = _artifacts(event)
    _, _, account = _function_arn(context)
    manifest = artifacts.get_json("manifest.json")
    findings = investigable(artifacts.get_json("diff.json").get("new") or [])
    ctx = RunContext(run_id=artifacts.run_id, account_id=account, started_at=manifest["started_at"],
                     lookback_from=manifest["lookback_from"])
    batches = make_batches(findings, ctx, settings.max_findings_per_investigation,
                           settings.investigation_description_max_bytes)
    artifacts.put_json(BATCHES_ARTIFACT, {"run_id": artifacts.run_id,
                                          "new_finding_ids": sorted(f["finding_id"] for f in findings),
                                          "batches": [b.to_dict() for b in batches]})
    log_event(log, "batched", run_id=artifacts.run_id, findings=len(findings),
              batches=[len(b.finding_ids) for b in batches])
    return {"run_id": artifacts.run_id, "batch_count": len(batches),
            "batches": [{"run_id": artifacts.run_id, "batch_n": b.batch_n, "batches": b.batches} for b in batches]}


def _load_batch(artifacts: Artifacts, batch_n: int) -> dict[str, Any]:
    for batch in artifacts.get_json(BATCHES_ARTIFACT).get("batches") or []:
        if batch.get("batch_n") == batch_n:
            return batch
    raise InputError(f"batch {batch_n} not found in {BATCHES_ARTIFACT}")


# --- investigate ---------------------------------------------------------------------------------

def _read_secret(parameter_name: str, region: str) -> str:
    if not parameter_name:
        raise WebhookConfigError("WEBHOOK_SECRET_PARAMETER_NAME is not configured")
    try:
        value = aws_clients.client("ssm", region).get_parameter(Name=parameter_name, WithDecryption=True)
        secret = value["Parameter"]["Value"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        raise WebhookConfigError(f"could not read the webhook signing secret ({code})") from None
    except (BotoCoreError, KeyError, TypeError) as exc:
        raise WebhookConfigError(f"could not read the webhook signing secret ({type(exc).__name__})") from None
    if not isinstance(secret, str) or not secret:
        raise WebhookConfigError("the webhook signing secret is empty")
    register_secret(secret)
    return secret


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Sign and POST one batch; store TOKEN#<incidentId>. The state machine discards the result."""
    settings = load_settings()
    log = get_logger("investigate", settings.log_level)
    task_token = event.get("task_token") if isinstance(event, dict) else None
    if not task_token or not isinstance(task_token, str):
        raise InputError("task_token is required")
    register_secret(task_token)
    batch_ref = event.get("batch") if isinstance(event.get("batch"), dict) else event
    batch_n = batch_ref.get("batch_n")
    if not isinstance(batch_n, int) or isinstance(batch_n, bool) or batch_n < 1:
        raise InputError("batch.batch_n must be a positive integer")
    artifacts = _artifacts(event)
    _, region, _ = _function_arn(context)

    url = settings.webhook_url
    register_secret(url)
    validate_url(url)
    url_region = webhook_region(url)
    if url_region != region:
        # Events land in the Agent Space's Region; a mismatch means every investigation would time out.
        raise WebhookConfigError(f"webhook Region {url_region} differs from this function's Region {region}")

    batch = _load_batch(artifacts, batch_n)
    secret = _read_secret(settings.webhook_secret_parameter_name, region)
    store = StateStore(aws_clients.table(settings.require("table_name")))
    now = _now()
    store.put_token(batch["incident_id"], task_token=task_token, run_id=artifacts.run_id, batch_n=batch_n,
                    finding_ids=batch["finding_ids"], finding_kinds=batch.get("finding_kinds") or {},
                    created_at=_iso(now),
                    ttl=int(now.timestamp()) + settings.investigation_timeout_seconds + TOKEN_TTL_MARGIN_SECONDS)
    ts = timestamp(now)
    body = build_body(batch, artifacts.run_id, ts)
    try:
        status = post(url, body, signed_headers(secret, ts, body), settings.webhook_timeout_seconds)
    except WebhookError as exc:
        store.consume_token(batch["incident_id"], _iso(_now()), f"failed:{type(exc).__name__}")
        log_event(log, "webhook_failed", logging.ERROR, run_id=artifacts.run_id, batch_n=batch_n,
                  incident_id=batch["incident_id"], error=type(exc).__name__, reason=str(exc))
        raise
    log_event(log, "investigation_requested", run_id=artifacts.run_id, batch_n=batch_n,
              incident_id=batch["incident_id"], findings=len(batch["finding_ids"]), http_status=status,
              priority=batch["priority"])
    return {"run_id": artifacts.run_id, "batch_n": batch_n, "incident_id": batch["incident_id"], "status": "posted"}


# --- MergeInvestigations -------------------------------------------------------------------------

def _failure_reason(result: dict[str, Any], token: dict[str, Any] | None) -> str:
    raw = result.get("reason") or result.get("error") or result.get("Error") or "unknown"
    if isinstance(raw, dict):  # a Catch ResultPath object: {"Error": ..., "Cause": ...}
        raw = raw.get("Error") or "unknown"
    error = str(raw)
    if error in _TIMEOUT_ERRORS:
        return "timeout-running" if (token or {}).get("started_at") else "timeout-never-started"
    return error[:120]


def merge_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    settings = load_settings()
    log = get_logger("merge", settings.log_level)
    artifacts = _artifacts(event)
    plan = artifacts.get_json(BATCHES_ARTIFACT)
    batches = plan.get("batches") or []
    store = StateStore(aws_clients.table(settings.require("table_name")))
    by_n: dict[int, dict[str, Any]] = {}
    for raw in event.get("results") or []:
        if not isinstance(raw, dict):
            continue
        item = {**raw, **raw["result"]} if isinstance(raw.get("result"), dict) else raw
        if isinstance(item.get("batch_n"), int):
            by_n[item["batch_n"]] = item
    outcomes: dict[int, dict[str, Any]] = {}
    kinds: dict[str, str] = {}
    now = _iso(_now())
    for batch in batches:
        n = batch["batch_n"]
        kinds.update(batch.get("finding_kinds") or {})
        item = by_n.get(n) or {"status": "failed", "reason": "no result"}
        token = store.get_token(batch["incident_id"])
        if item.get("status") == "ok":
            outcomes[n] = {"status": "ok", "result": artifacts.get_json(f"investigation-{n}.json")}
        else:
            outcomes[n] = {"status": "failed", "reason": _failure_reason(item, token)}
        if token and not token.get("consumed_at"):
            store.consume_token(batch["incident_id"], now, f"merged:{outcomes[n]['status']}")
    merged = merge_investigations(plan.get("new_finding_ids") or [], batches, outcomes, kinds)
    if not merged["invariant"]["ok"]:
        # A batching bug, not an agent error: surfaced as a system line in the report (task 3.5).
        log_event(log, "merge_invariant_violated", logging.ERROR, run_id=artifacts.run_id,
                  invariant=merged["invariant"])
    artifacts.put_json(MERGED_ARTIFACT, merged)
    stamp = int(_now().timestamp() * 1000)
    print(report_core.emf_metrics(METRIC_NAMESPACE,  # noqa: T201 - EMF must be a raw stdout line
                                  {"InvestigationFailed": merged["failed_batches"]}, stamp))
    log_event(log, "merged", run_id=artifacts.run_id, ok=merged["ok_batches"], failed=merged["failed_batches"],
              incidents=len(merged["incidents"]))
    return {"run_id": artifacts.run_id, "ok_batches": merged["ok_batches"], "failed_batches": merged["failed_batches"],
            "invariant_ok": merged["invariant"]["ok"],
            "batches": [{"batch_n": b["batch_n"], "status": b["status"]} for b in merged["batches"]]}
