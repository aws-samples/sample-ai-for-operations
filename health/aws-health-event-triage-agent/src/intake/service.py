# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Intake service — stateful orchestration for the Intake Lambda.

Separates business logic from the Lambda handler for testability.
All AWS calls are injectable (default to real boto3 clients).

Flow (Intake Lambda, per message — process_message):
  validate_and_parse -> check_idempotency -> load_existing ->
  merge_record -> enrich_accounts -> save_record ->
  enqueue_settle_message

Flow (settle consumer Lambda, per settled (eventArn, lastUpdatedTime) —
start_settled_workflow):
  start_workflow_execution

Working spec feat-devops-agent-enrichment, req §1b / design §3.0 (task -1b):
process_message() used to call start_workflow_execution directly on every
message. AWS Health's organizational-view feed delivers one message per
(affectedAccount, page) for a single AWS update — several messages can
arrive within seconds, each merging a different account into the SAME
ConsolidatedEvents record. Starting the workflow on message 1 meant it read
a record that might still be missing accounts from messages 2..N. This
split defers the actual StartExecution to a settle consumer that only runs
after every message's settle-queue entry has cleared its delay
(INTAKE_SETTLE_SECONDS), so by the time it starts the workflow, the record
is settled. The fixed (eventArn, lastUpdatedTime) execution name is kept
unchanged, so N settle messages for one AWS update still collapse to one
execution via ExecutionAlreadyExists — that safety net was already correct
and needed no change.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

import boto3

from src import config
from src.intake.event_parser import HealthEventParseError, idempotency_key, parse_health_event
from src.intake.merge_event_message import consolidated_to_db, merge_event_message

logger = logging.getLogger(__name__)

# TTL for idempotency records: 30 days in seconds
IDEMPOTENCY_TTL_SECONDS = 30 * 24 * 60 * 60

# TTL for account context cache: configurable, default 24h
ACCOUNT_CONTEXT_TTL_SECONDS = int(
    config.AWS_REGION  # placeholder; real config key added in later phase
    and 24 * 60 * 60
    or 24 * 60 * 60
)


def _workflow_execution_name(event_arn: str, last_updated_time: str) -> str:
    """Return the Step Functions execution name: sha256(eventArn+lastUpdatedTime)[:64]."""
    raw = f"{event_arn}{last_updated_time}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (Z suffix)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _event_arn_hash(event_arn: str) -> str:
    """Return a stable hash of an eventArn, safe for use as an S3 key
    prefix (an eventArn contains ':' and '/' characters that are legal in
    S3 keys but make hand-inspecting the bucket harder, and the design
    explicitly calls for hashing — design §3.6: "the hash avoids ':'/'/'
    in the key.")"""
    return hashlib.sha256(event_arn.encode()).hexdigest()[:32]


def _snapshot_key(event_arn: str, last_updated_time: str) -> str:
    """Return the S3 key for an event snapshot: events/<eventArn-hash>/<lastUpdatedTime>.json
    (design §3.6, req E7.1). last_updated_time's colons are replaced with
    '-' so the key contains no ':' at all, matching the hash prefix's own
    S3-key-friendliness goal (a raw ISO timestamp like
    2027-01-01T00:00:00Z is technically a legal S3 key already, but this
    keeps the whole key visually consistent and avoids any tooling that
    treats ':' specially, e.g. some URL encoders)."""
    safe_timestamp = last_updated_time.replace(":", "-")
    return f"events/{_event_arn_hash(event_arn)}/{safe_timestamp}.json"


class IntakeService:
    """Orchestrates the intake pipeline for a single health event message."""

    def __init__(
        self,
        *,
        dynamodb_client=None,
        stepfunctions_client=None,
        sqs_client=None,
        s3_client=None,
        consolidated_table_name: str = "",
        idempotency_table_name: str = "",
        account_cache_table_name: str = "",
        ticket_map_table_name: str = "",
        audit_log_table_name: str = "",
        workflow_arn: str = "",
        settle_queue_url: str = "",
        settle_seconds: int | None = None,
        snapshot_bucket_name: str = "",
    ):
        self._ddb = dynamodb_client or boto3.client("dynamodb", region_name=config.AWS_REGION)
        self._sfn = stepfunctions_client or boto3.client(
            "stepfunctions", region_name=config.AWS_REGION
        )
        self._sqs = sqs_client or boto3.client("sqs", region_name=config.AWS_REGION)
        self._s3 = s3_client or boto3.client("s3", region_name=config.AWS_REGION)
        self._consolidated_table = consolidated_table_name or config.CONSOLIDATED_TABLE_NAME
        self._idempotency_table = idempotency_table_name or config.IDEMPOTENCY_TABLE_NAME
        self._account_cache_table = account_cache_table_name or config.ACCOUNT_CACHE_TABLE_NAME
        self._ticket_map_table = ticket_map_table_name or config.TICKET_MAP_TABLE_NAME
        self._audit_log_table = audit_log_table_name or config.AUDIT_LOG_TABLE_NAME
        self._workflow_arn = workflow_arn or config.TRIAGE_WORKFLOW_ARN
        self._settle_queue_url = settle_queue_url or config.SETTLE_QUEUE_URL
        self._settle_seconds = (
            settle_seconds if settle_seconds is not None else config.INTAKE_SETTLE_SECONDS
        )
        self._snapshot_bucket_name = snapshot_bucket_name or config.EVENT_SNAPSHOT_BUCKET

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_message(self, raw_message: dict) -> dict:
        """Process one SQS message body (EventBridge envelope or bare detail).

        Returns a result dict with status and event_arn for batch item failure
        reporting.
        """
        event_arn = "(unknown)"
        try:
            parsed = parse_health_event(raw_message)
        except HealthEventParseError as exc:
            logger.error(
                json.dumps({
                    "message": "Failed to parse health event",
                    "error": str(exc),
                    "raw_keys": list(raw_message.keys()) if isinstance(raw_message, dict) else [],
                })
            )
            return {"status": "parse_error", "event_arn": event_arn, "error": str(exc)}

        event_arn = parsed["eventArn"]
        ikey = idempotency_key(parsed)

        # Step 1: idempotency check
        if self._is_duplicate(ikey):
            logger.info(
                json.dumps({
                    "message": "Duplicate message — skipping",
                    "event_arn": event_arn,
                    "idempotency_key": ikey,
                })
            )
            return {"status": "duplicate", "event_arn": event_arn}

        # Step 2: load existing consolidated record
        existing = self._load_consolidated(event_arn)

        # Step 3: merge
        merged = merge_event_message(existing, parsed)

        # Step 3a: stamp lastMessageAt (design §3.0 settle window) — the
        # settle consumer does not read this today (the fixed execution
        # name already collapses duplicate StartExecution calls), but it is
        # recorded on every merge so a future watermark-based settle
        # strategy (or an operator inspecting the record) can see when this
        # event was last touched.
        merged["lastMessageAt"] = _now_iso()

        # Step 4: save. snapshotKey is stamped onto the record BEFORE
        # writing the snapshot body (so the body doesn't self-referentially
        # contain its own not-yet-known key) but only when a snapshot
        # bucket is actually configured — stamping a key that will never
        # be written would let a downstream reader trust a snapshotKey
        # pointing at an object that doesn't exist. The key itself, when
        # stamped, is computed deterministically from (eventArn,
        # lastUpdatedTime) — see _snapshot_key() — so stamping it here and
        # writing the object after (below) is safe; both derive the
        # identical key.
        merged["snapshotKey"] = (
            _snapshot_key(event_arn, parsed["lastUpdatedTime"]) if self._snapshot_bucket_name else ""
        )
        db_item = consolidated_to_db(merged)
        self._save_consolidated(db_item)

        # Step 4a: write the full event snapshot to S3 (req E7.1, design
        # §3.6, task 8) — the merged record (including its own snapshotKey
        # field, so a downstream reader of the snapshot itself can see
        # which key it was stored under), so the snapshot always reflects
        # everything received so far for this (eventArn, lastUpdatedTime),
        # including entities and pages merged from earlier messages in the
        # same fan-out. Also stamped onto the ConsolidatedEvents record
        # itself (via merged["snapshotKey"] above) so the workflow's
        # LoadEvent step (src/classifier/worker_handler.py) can read it
        # back from $.event.snapshotKey and forward it into the enrichment
        # webhook's [EVENT_SNAPSHOT:...] tag (task 5/11) without a second
        # S3 round-trip or a separate DynamoDB field.
        snapshot_key = self._write_snapshot(event_arn, parsed["lastUpdatedTime"], db_item)

        # Step 5: mark idempotency
        self._mark_idempotency(ikey)

        # Step 6: write audit record
        self._write_audit(event_arn, ikey, "intake", {"pages_received": sorted(merged["pagesReceived"])})

        # Step 7: enqueue a settle-window message (design §3.0). Deferred to
        # the settle consumer's start_settled_workflow() — never started
        # here — so the workflow reads the record only after every message
        # for this (eventArn, lastUpdatedTime) has had time to merge.
        self._enqueue_settle_message(event_arn, parsed["lastUpdatedTime"])

        logger.info(
            json.dumps({
                "message": "Health event processed",
                "event_arn": event_arn,
                "status_code": parsed["statusCode"],
                "accounts_total": len(merged["affectedAccounts"]),
                "snapshot_key": snapshot_key,
            })
        )
        return {"status": "processed", "event_arn": event_arn, "snapshot_key": snapshot_key}

    # ------------------------------------------------------------------
    # DynamoDB helpers
    # ------------------------------------------------------------------

    def _is_duplicate(self, ikey: str) -> bool:
        try:
            resp = self._ddb.get_item(
                TableName=self._idempotency_table,
                Key={"pk": {"S": ikey}},
                ConsistentRead=True,
            )
            return "Item" in resp
        except Exception as exc:
            logger.warning(
                json.dumps({"message": "Idempotency check failed — treating as non-duplicate", "error": str(exc)})
            )
            return False

    def _mark_idempotency(self, ikey: str) -> None:
        ttl = int(time.time()) + IDEMPOTENCY_TTL_SECONDS
        try:
            self._ddb.put_item(
                TableName=self._idempotency_table,
                Item={"pk": {"S": ikey}, "ttl": {"N": str(ttl)}},
            )
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to write idempotency record", "error": str(exc)}))

    def _load_consolidated(self, event_arn: str) -> dict | None:
        try:
            resp = self._ddb.get_item(
                TableName=self._consolidated_table,
                Key={"eventArn": {"S": event_arn}},
                ConsistentRead=True,
            )
            item = resp.get("Item")
            if not item:
                return None
            record = _ddb_deserialize(item)
            # merge_event_message()'s documented contract requires
            # 'affectedEntities' to be a dict keyed by entityValue (its
            # in-memory working shape) — but consolidated_to_db() converts
            # it to a list before every DynamoDB write, for stable
            # serialization. Reversing that conversion on load was missing
            # entirely: a real second message for an already-consolidated
            # event (any event updated after its first message) crashed
            # merge_event_message with "ValueError: dictionary update
            # sequence element #0 has length 6; 2 is required" trying to
            # dict() a list of entity dicts. Every existing test only ever
            # sent one message per event, or used an empty affectedEntities
            # list (for which dict([]) happens to succeed), so this was
            # never exercised until a real second message hit a real
            # deployed event during live-deploy validation.
            raw_entities = record.get("affectedEntities")
            if isinstance(raw_entities, list):
                record["affectedEntities"] = {
                    e.get("entityValue", ""): e for e in raw_entities if isinstance(e, dict)
                }
            return record
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to load consolidated record", "event_arn": event_arn, "error": str(exc)}))
            return None

    def _save_consolidated(self, record: dict) -> None:
        try:
            self._ddb.put_item(
                TableName=self._consolidated_table,
                Item=_ddb_serialize(record),
            )
        except Exception as exc:
            # nosemgrep: logging-error-without-handling -- logging for troubleshooting before re-raising
            logger.error(json.dumps({"message": "Failed to save consolidated record", "event_arn": record.get("eventArn"), "error": str(exc)}))
            raise

    # ------------------------------------------------------------------
    # Event snapshot (S3) — req E7.1, design §3.6, task 8
    # ------------------------------------------------------------------

    def _write_snapshot(self, event_arn: str, last_updated_time: str, record: dict) -> str:
        """Writes the full consolidated event to S3 as a JSON snapshot.

        Called on every create/update (req E7.1) — a real per-message
        write, not deduplicated across messages of the same fan-out, so
        each snapshot reflects the merged state at the moment of that
        specific message (the LAST message's snapshot for one
        lastUpdatedTime is the complete one; earlier ones are partial,
        exactly like ConsolidatedEvents itself before the settle window
        elapses — the settle window governs when the WORKFLOW reads the
        record, not how many snapshots get written).

        Never raises — a snapshot write failure must not block intake
        (the settle window and workflow will simply proceed with whatever
        snapshot key was returned, or Notify will show enrichment
        unavailable for a webhook that references a key that never wrote,
        which is a visible, honest degraded case per design §6 — not a
        silent one).

        Returns:
            The S3 key written, or "" if EVENT_SNAPSHOT_BUCKET is not
            configured (matching the other optional-feature no-op pattern
            in this module, e.g. _enqueue_settle_message when
            SETTLE_QUEUE_URL is empty).
        """
        if not self._snapshot_bucket_name:
            logger.info(
                json.dumps({"message": "No EVENT_SNAPSHOT_BUCKET configured — skipping snapshot write"})
            )
            return ""

        key = _snapshot_key(event_arn, last_updated_time)
        try:
            # record's 'pagesReceived' may be a Python set (consolidated_to_db
            # already converts it to a sorted list, but this method accepts
            # any dict — defend against a caller passing the pre-conversion
            # shape too, since json.dumps cannot serialise a set).
            body = json.dumps(record, default=lambda o: sorted(o) if isinstance(o, set) else str(o))
            self._s3.put_object(
                Bucket=self._snapshot_bucket_name,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
            )
            return key
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "Failed to write event snapshot to S3",
                    "event_arn": event_arn,
                    "bucket": self._snapshot_bucket_name,
                    "key": key,
                    "error": str(exc),
                })
            )
            return ""

    def _write_audit(self, event_arn: str, ikey: str, step: str, extra: dict) -> None:
        import time as _time
        try:
            ts = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
            self._ddb.put_item(
                TableName=self._audit_log_table,
                Item=_ddb_serialize({
                    "executionId": ikey,
                    "timestamp": ts,
                    "eventArn": event_arn,
                    "step": step,
                    **extra,
                }),
            )
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to write audit record", "error": str(exc)}))

    # ------------------------------------------------------------------
    # Settle window (design §3.0) — SQS delay queue + settle consumer
    # ------------------------------------------------------------------

    def _enqueue_settle_message(self, event_arn: str, last_updated_time: str) -> None:
        """Send a delayed settle message for this (eventArn, lastUpdatedTime).

        Called once per intake message — N intake messages for one AWS
        update produce N settle messages, all with the same delay. The
        settle consumer (start_settled_workflow) that eventually processes
        them still only starts ONE execution, because the execution name is
        fixed per (eventArn, lastUpdatedTime); the N-1 extra
        start_execution calls fail on ExecutionAlreadyExists and are
        swallowed exactly as before this change.
        """
        if not self._settle_queue_url:
            logger.info(
                json.dumps({"message": "No SETTLE_QUEUE_URL configured — skipping settle enqueue"})
            )
            return
        try:
            self._sqs.send_message(
                QueueUrl=self._settle_queue_url,
                MessageBody=json.dumps({"eventArn": event_arn, "lastUpdatedTime": last_updated_time}),
                DelaySeconds=self._settle_seconds,
            )
        except Exception as exc:
            logger.warning(
                json.dumps({
                    "message": "Failed to enqueue settle message",
                    "event_arn": event_arn,
                    "error": str(exc),
                })
            )

    def start_settled_workflow(self, event_arn: str, last_updated_time: str) -> dict:
        """Start the TriageWorkflow execution for a settled event.

        Called by the settle consumer Lambda (src/intake/settle_handler.py)
        once a settle-queue message's delay has elapsed — i.e. after
        INTAKE_SETTLE_SECONDS have passed since that message was enqueued,
        by which point every message for this (eventArn, lastUpdatedTime)
        has had time to merge into ConsolidatedEvents (design §3.0). This is
        the ONLY place that calls StartExecution; process_message() never
        does.

        Uses the same execution name as before this change
        (sha256(eventArn + lastUpdatedTime)[:64]) so N settle messages for
        one AWS update still collapse to exactly one execution.
        """
        execution_name = _workflow_execution_name(event_arn, last_updated_time)
        self._start_workflow(event_arn, execution_name)
        return {"event_arn": event_arn, "execution_name": execution_name}

    # ------------------------------------------------------------------
    # Step Functions helpers
    # ------------------------------------------------------------------

    def _start_workflow(self, event_arn: str, execution_name: str) -> None:
        if not self._workflow_arn:
            logger.info(json.dumps({"message": "No TRIAGE_WORKFLOW_ARN configured — skipping Step Functions"}))
            return
        try:
            self._sfn.start_execution(
                stateMachineArn=self._workflow_arn,
                name=execution_name,
                input=json.dumps({"eventArn": event_arn}),
            )
        except self._sfn.exceptions.ExecutionAlreadyExists:
            logger.info(json.dumps({"message": "Workflow execution already exists", "execution_name": execution_name}))
        except Exception as exc:
            logger.warning(json.dumps({"message": "Failed to start workflow execution", "event_arn": event_arn, "error": str(exc)}))


# ---------------------------------------------------------------------------
# Simple DynamoDB serialize/deserialize helpers
# (production code would use boto3 TypeSerializer; keeping minimal for now)
# ---------------------------------------------------------------------------

def _ddb_serialize(obj: dict) -> dict:
    """Minimal DynamoDB item serializer for str/int/list/dict/set types."""
    result: dict = {}
    for k, v in obj.items():
        if isinstance(v, str):
            result[k] = {"S": v}
        elif isinstance(v, bool):
            result[k] = {"BOOL": v}
        elif isinstance(v, int):
            result[k] = {"N": str(v)}
        elif isinstance(v, float):
            result[k] = {"N": str(v)}
        elif isinstance(v, list):
            result[k] = {"S": json.dumps(v)}  # serialize complex types as JSON string
        elif isinstance(v, dict):
            result[k] = {"S": json.dumps(v)}
        elif isinstance(v, set):
            result[k] = {"S": json.dumps(sorted(v))}
        else:
            result[k] = {"S": str(v)}
    return result


def _ddb_deserialize(item: dict) -> dict:
    """Minimal DynamoDB item deserializer."""
    result: dict = {}
    for k, v in item.items():
        if "S" in v:
            s_val = v["S"]
            # Try to parse back JSON for complex types
            try:
                parsed = json.loads(s_val)
                result[k] = parsed
            except (json.JSONDecodeError, TypeError):
                result[k] = s_val
        elif "N" in v:
            n_str = v["N"]
            result[k] = float(n_str) if "." in n_str else int(n_str)
        elif "BOOL" in v:
            result[k] = v["BOOL"]
        else:
            result[k] = v
    return result
