# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`callback`: DevOps Agent `aws.aidevops` EventBridge events -> Step Functions task responses.

Design refs: D§3.3 (transport, correlation, results), D§3.3a (cross-account), D§3.4 (progress),
D§6.3 (validation, ranking); tasks.md 3.3.

Flow per event:
1. Ignore unknown detail-types, events without `execution_id`, and other Agent Spaces.
2. Correlate: the first `message` journal record (ListJournalRecords, order=ASC, limit=1) must be
   our webhook text with an `[INVESTIGATION_ID:nrdc-...]` tag, and TOKEN#<id> must be live.
   Anything else belongs to another investigation and is dropped.
3. Progress (Created / In Progress / Priority Updated): SendTaskHeartbeat, set started_at.
   Failed / Timed Out / Cancelled / Skipped / Linked: SendTaskFailure(error=<detail-type>).
   Completed: read the summary record (fallback: last assistant message), extract the fenced
   nrdc-investigation/v1 block, validate it for THIS batch, recompute scores, write
   runs/<run_id>/investigation-<batch>.json, SendTaskSuccess. No parseable block (none found, or
   not JSON in either source): NO_RESULT. A block that fails batch-scoped validation: SCHEMA_INVALID.

Journal access denied (AssumeRole or ListJournalRecords): without the journal the event cannot be
correlated, so the callback cannot tell which batch it belongs to. Every outstanding token (the
META#live-investigations set) is failed with JOURNAL_ACCESS_DENIED instead: none of them could
ever complete, and failing them now beats waiting for the timeout. If no token is outstanding, the
denial is logged and re-raised, so async-invoke retries and then the DLQ (CallbackDlqMessages
alarm) surface it. It is never dropped silently. A denial after correlation fails that one token.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError

from config import Settings, load_settings
from drift_core.artifacts import Artifacts
from drift_core.cross_account import is_cross_account, journal_reader_role_arn, parse_function_arn
from drift_core.investigation import (
    SCHEMA_ID,
    extract_block,
    extract_investigation_id,
    normalize,
    validate_result,
)
from drift_core.logging_util import get_logger, log_event, register_secret
from drift_core.state_store import StateStore
from handlers import aws_clients

COMPLETED = "Investigation Completed"
FAILURES = ("Investigation Failed", "Investigation Timed Out", "Investigation Cancelled",
            "Investigation Skipped", "Investigation Linked")
PROGRESS = ("Investigation Created", "Investigation In Progress", "Investigation Priority Updated")
NO_RESULT, SCHEMA_INVALID, JOURNAL_ACCESS_DENIED = "NO_RESULT", "SCHEMA_INVALID", "JOURNAL_ACCESS_DENIED"
SUMMARY_RECORD_TYPE = "investigation_summary_md"
MESSAGE_RECORD_TYPE = "message"
SESSION_NAME = "nrdc-callback"
_DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "InvalidClientTokenId",
           "ExpiredToken", "UnrecognizedClientException"}
_TOKEN_GONE = {"TaskTimedOut", "TaskDoesNotExist", "InvalidToken"}
_CAUSE_MAX = 4000


class JournalAccessDenied(Exception):
    """The journal of the Agent Space could not be read (IAM or the cross-account role)."""


# --- Journal ------------------------------------------------------------------------------------

class Journal:
    """ListJournalRecords against the Agent Space. In the cross-account shape the client is built
    from sts:AssumeRole credentials for the journal-reader role, assumed once per invocation."""

    def __init__(self, settings: Settings, partition: str, region: str, own_account: str) -> None:
        self._settings, self._partition, self._region, self._own = settings, partition, region, own_account
        self._client: Any = None

    @property
    def cross_account(self) -> bool:
        return is_cross_account(self._settings.devops_agent_account_id, self._own)

    def _get(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.cross_account:
            self._client = aws_clients.client("devops-agent", self._region)
            return self._client
        role_arn = journal_reader_role_arn(self._settings.devops_agent_account_id, self._own, self._region,
                                           self._partition)
        try:
            creds = aws_clients.client("sts", self._region).assume_role(
                RoleArn=role_arn, RoleSessionName=SESSION_NAME, DurationSeconds=900)["Credentials"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            if code in _DENIED:
                raise JournalAccessDenied(f"sts:AssumeRole on {role_arn} denied ({code})") from None
            raise
        register_secret(creds.get("SecretAccessKey"))
        register_secret(creds.get("SessionToken"))
        self._client = aws_clients.assumed_client("devops-agent", self._region, creds)
        return self._client

    def records(self, space: str, execution: str, record_type: str, order: str, limit: int,
                max_pages: int = 1) -> Iterator[dict[str, Any]]:
        client = self._get()
        kwargs: dict[str, Any] = {"agentSpaceId": space, "executionId": execution, "recordType": record_type,
                                  "order": order, "limit": limit}
        for _ in range(max_pages):
            try:
                page = client.list_journal_records(**kwargs)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                if code in _DENIED:
                    raise JournalAccessDenied(f"aidevops:ListJournalRecords denied ({code})") from None
                raise
            yield from page.get("records") or []
            if not page.get("nextToken"):
                return
            kwargs["nextToken"] = page["nextToken"]


def _parse(content: Any) -> Any:
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content
    return content


def _message_text(message: dict[str, Any]) -> str:
    parts = message.get("content")
    if isinstance(parts, str):
        return parts
    if isinstance(parts, list):
        return "\n\n".join(p["text"] for p in parts
                           if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str))
    return ""


def _all_text(content: Any) -> str:
    """Every string inside a document-typed record (the summary record's shape is not fixed)."""
    value = _parse(content)
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(_all_text(v) for v in value.values())
    if isinstance(value, list):
        return "\n".join(_all_text(v) for v in value)
    return ""


def first_user_text(journal: Journal, space: str, execution: str) -> str | None:
    for record in journal.records(space, execution, MESSAGE_RECORD_TYPE, "ASC", 1):
        message = _parse(record.get("content"))
        if isinstance(message, dict) and message.get("role") == "user":
            return _message_text(message)
        return None
    return None


def summary_text(journal: Journal, space: str, execution: str, record_id: str) -> str | None:
    for record in journal.records(space, execution, SUMMARY_RECORD_TYPE, "ASC", 100, max_pages=10):
        if record.get("recordId") == record_id:
            return _all_text(record.get("content"))
    return None


def last_assistant_text(journal: Journal, space: str, execution: str) -> str | None:
    """The newest assistant message that carries the result block, else the newest assistant
    message. DevOps Agent keeps posting after its conclusion (mitigation follow-ups, seen live
    2026-10-15), so the block is not necessarily in the very last message."""
    latest: str | None = None
    for record in journal.records(space, execution, MESSAGE_RECORD_TYPE, "DESC", 20, max_pages=5):
        message = _parse(record.get("content"))
        if isinstance(message, dict) and message.get("role") == "assistant":
            text = _message_text(message)
            if SCHEMA_ID in text:
                return text
            if latest is None:
                latest = text
    return latest


# --- Step Functions -----------------------------------------------------------------------------

def _send(sfn: Any, operation: str, log: logging.Logger, **kwargs: Any) -> bool:
    """Call SendTask*; a token Step Functions no longer knows (timed out, already used) is not an error."""
    try:
        getattr(sfn, operation)(**kwargs)
        return True
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _TOKEN_GONE:
            log_event(log, "task_token_gone", logging.WARNING, operation=operation, error=code)
            return False
        raise


def _fail(sfn: Any, store: StateStore, log: logging.Logger, token: dict[str, Any], error: str, cause: str,
          now: str) -> None:
    _send(sfn, "send_task_failure", log, taskToken=token["task_token"], error=error, cause=cause[:_CAUSE_MAX])
    store.consume_token(token["incident_id"], now, f"failed:{error}")
    log_event(log, "batch_failed", logging.WARNING, incident_id=token["incident_id"], run_id=token.get("run_id"),
              error=error, cause=cause[:_CAUSE_MAX])


def _fail_outstanding(sfn: Any, store: StateStore, log: logging.Logger, reason: str, now: str,
                      now_epoch: int) -> int:
    failed = 0
    for incident_id in store.live_incident_ids():
        token = store.live_token(incident_id, now_epoch)
        if token is None:
            store.consume_token(incident_id, now, "expired")
            continue
        register_secret(token.get("task_token"))
        _fail(sfn, store, log, token, JOURNAL_ACCESS_DENIED, reason, now)
        failed += 1
    return failed


def _result_block(journal: Journal, space: str, execution: str,
                  data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """The summary record first, then the last assistant message; the first parseable block wins.
    Returns ('ok', doc), ('invalid', None) if a block was found but none parsed, or ('none', None)."""
    first = "none"
    if data.get("summary_record_id"):
        first, doc = extract_block(summary_text(journal, space, execution, data["summary_record_id"]) or "")
        if first == "ok":
            return first, doc
    second, doc = extract_block(last_assistant_text(journal, space, execution) or "")
    if second == "ok":
        return second, doc
    return ("invalid" if "invalid" in (first, second) else "none"), None


def _complete(journal: Journal, sfn: Any, store: StateStore, log: logging.Logger, settings: Settings,
              token: dict[str, Any], meta: dict[str, Any], data: dict[str, Any], now: str) -> str:
    space, execution = meta["agent_space_id"], meta["execution_id"]
    status, doc = _result_block(journal, space, execution, data)
    if status != "ok" or doc is None:
        # tasks.md 3.3: completed without a *parseable* block -> NO_RESULT.
        cause = ("the nrdc-investigation/v1 block is not valid JSON" if status == "invalid"
                 else "investigation completed without an nrdc-investigation/v1 block")
        _fail(sfn, store, log, token, NO_RESULT, cause, now)
        return NO_RESULT
    errors = validate_result(doc, token["incident_id"], list(token.get("finding_ids") or []))
    if errors:
        _fail(sfn, store, log, token, SCHEMA_INVALID, "; ".join(errors[:10]), now)
        return SCHEMA_INVALID
    default_url = f"https://{space}.aidevops.global.app.aws/investigation/{meta.get('task_id', '')}"
    result = normalize(doc, finding_kinds=dict(token.get("finding_kinds") or {}),
                       production_values=settings.production_tag_values, default_url=default_url)
    batch_n = int(token["batch_n"])
    result.update({"run_id": token["run_id"], "batch_n": batch_n, "task_id": meta.get("task_id"),
                   "execution_id": execution})
    artifacts = Artifacts(aws_clients.client("s3"), settings.require("bucket_name"), token["run_id"])
    key = artifacts.put_json(f"investigation-{batch_n}.json", result)
    output = {"batch_n": batch_n, "status": "ok", "incident_id": token["incident_id"], "artifact": key,
              "incident_count": len(result["incidents"]), "investigation_url": result["investigation_url"]}
    sent = _send(sfn, "send_task_success", log, taskToken=token["task_token"], output=json.dumps(output))
    store.consume_token(token["incident_id"], now, "ok" if sent else "expired")
    log_event(log, "batch_succeeded", incident_id=token["incident_id"], run_id=token["run_id"],
              incidents=len(result["incidents"]), unassigned=len(result["unassigned_finding_ids"]))
    return "ok"


def handler(event: dict[str, Any], context: Any = None) -> dict[str, str]:
    settings = load_settings()
    log = get_logger("callback", settings.log_level)
    detail_type = event.get("detail-type") if isinstance(event, dict) else None
    detail = event.get("detail") if isinstance(event, dict) and isinstance(event.get("detail"), dict) else {}
    meta = detail.get("metadata") if isinstance(detail.get("metadata"), dict) else {}
    data = detail.get("data") if isinstance(detail.get("data"), dict) else {}
    if detail_type not in (COMPLETED, *FAILURES, *PROGRESS):
        log_event(log, "event_ignored", detail_type=detail_type, reason="detail-type not handled")
        return {"status": "ignored"}
    space, execution = meta.get("agent_space_id"), meta.get("execution_id")
    if not execution or not space:
        log_event(log, "event_ignored", detail_type=detail_type, reason="no execution_id")
        return {"status": "ignored"}
    if settings.devops_agent_space_id and space != settings.devops_agent_space_id:
        log_event(log, "event_ignored", detail_type=detail_type, reason="other Agent Space")
        return {"status": "ignored"}

    partition, region, own_account = parse_function_arn(getattr(context, "invoked_function_arn", ""))
    store = StateStore(aws_clients.table(settings.require("table_name")))
    sfn = aws_clients.client("stepfunctions", region)
    journal = Journal(settings, partition, region, own_account)
    moment = dt.datetime.now(dt.UTC)
    now, now_epoch = moment.strftime("%Y-%m-%dT%H:%M:%SZ"), int(moment.timestamp())

    try:
        text = first_user_text(journal, space, execution)
    except JournalAccessDenied as exc:
        failed = _fail_outstanding(sfn, store, log, str(exc), now, now_epoch)
        log_event(log, "journal_access_denied", logging.ERROR, detail_type=detail_type,
                  cross_account=journal.cross_account, reason=str(exc), batches_failed=failed)
        if failed == 0:
            raise
        return {"status": JOURNAL_ACCESS_DENIED}
    incident_id = extract_investigation_id(text or "")
    if not incident_id:
        log_event(log, "event_dropped", detail_type=detail_type, reason="first message has no nrdc tag")
        return {"status": "dropped"}
    token = store.live_token(incident_id, now_epoch)
    if token is None:
        log_event(log, "event_dropped", detail_type=detail_type, incident_id=incident_id,
                  reason="no live TOKEN# item")
        return {"status": "dropped"}
    register_secret(token.get("task_token"))

    if detail_type in PROGRESS:
        if _send(sfn, "send_task_heartbeat", log, taskToken=token["task_token"]):
            store.mark_started(incident_id, now, detail_type)
        else:
            store.consume_token(incident_id, now, "expired")
        log_event(log, "heartbeat", incident_id=incident_id, detail_type=detail_type)
        return {"status": "heartbeat"}
    if detail_type in FAILURES:
        _fail(sfn, store, log, token, detail_type, f"{detail_type} (task {meta.get('task_id')})", now)
        return {"status": "failed"}
    try:
        return {"status": _complete(journal, sfn, store, log, settings, token, meta, data, now)}
    except JournalAccessDenied as exc:
        _fail(sfn, store, log, token, JOURNAL_ACCESS_DENIED, str(exc), now)
        return {"status": JOURNAL_ACCESS_DENIED}
