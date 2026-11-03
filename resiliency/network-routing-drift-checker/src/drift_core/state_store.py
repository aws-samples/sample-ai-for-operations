# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Drift-state table I/O (design.md D§5.1). Uses the boto3 DynamoDB Table resource.

Items:  F#<finding_id>  finding history (GSI `status-index` on `status`, sparse)
        META#marker     last successful full-scope run (lookback origin)
        RUN#<run_id>    operational history (TTL 90 days)
        TOKEN#<incidentId>          investigation task token (TTL = investigation timeout + margin)
        META#live-investigations    incidentIds with an outstanding TOKEN#
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

STATUS_INDEX = "status-index"
MARKER_PK = "META#marker"
TOKEN_PREFIX = "TOKEN#"  # noqa: S105 - a DynamoDB key prefix, not a credential  # nosec B105 -- same reason, Bandit's own marker
# String set of incidentIds whose TOKEN# is outstanding. Lets the callback fail them with
# JOURNAL_ACCESS_DENIED when it cannot read the journal (and so cannot correlate the event).
LIVE_PK = "META#live-investigations"
RUN_TTL_DAYS = 90


class StateStore:
    def __init__(self, table: Any) -> None:
        self._table = table

    def load_open(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {"IndexName": STATUS_INDEX, "KeyConditionExpression": Key("status").eq("open")}
        while True:
            resp = self._table.query(**kwargs)
            items.extend(resp.get("Items") or [])
            if "LastEvaluatedKey" not in resp:
                return items
            kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    def write_items(self, items: list[dict[str, Any]]) -> None:
        with self._table.batch_writer(overwrite_by_pkeys=["pk"]) as batch:
            for item in items:
                batch.put_item(Item=item)

    def get_marker(self) -> str | None:
        item = self._table.get_item(Key={"pk": MARKER_PK}).get("Item")
        return item.get("last_successful_full_run") if item else None

    # --- Investigation task tokens (design.md D§3.3). Items carry no `status` attribute, so they
    # stay out of the sparse status-index that `load_open` queries.

    def put_token(self, incident_id: str, *, task_token: str, run_id: str, batch_n: int, finding_ids: list[str],
                  finding_kinds: dict[str, str], created_at: str, ttl: int) -> None:
        self._table.put_item(Item={
            "pk": f"{TOKEN_PREFIX}{incident_id}", "incident_id": incident_id, "task_token": task_token,
            "run_id": run_id, "batch_n": batch_n, "finding_ids": list(finding_ids),
            "finding_kinds": dict(finding_kinds), "created_at": created_at, "ttl": ttl})
        self._table.update_item(Key={"pk": LIVE_PK}, UpdateExpression="ADD incident_ids :i",
                                ExpressionAttributeValues={":i": {incident_id}})

    def get_token(self, incident_id: str) -> dict[str, Any] | None:
        return self._table.get_item(Key={"pk": f"{TOKEN_PREFIX}{incident_id}"}, ConsistentRead=True).get("Item")

    def live_token(self, incident_id: str, now_epoch: int) -> dict[str, Any] | None:
        """The token item if it exists, has not been consumed, and its TTL has not passed."""
        item = self.get_token(incident_id)
        if not item or item.get("consumed_at") or int(item.get("ttl", 0)) <= now_epoch:
            return None
        return item

    def mark_started(self, incident_id: str, now: str, detail_type: str) -> None:
        try:
            self._table.update_item(
                Key={"pk": f"{TOKEN_PREFIX}{incident_id}"},
                UpdateExpression="SET started_at = if_not_exists(started_at, :now), last_progress = :d",
                ConditionExpression="attribute_exists(pk)",
                ExpressionAttributeValues={":now": now, ":d": detail_type})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise

    def consume_token(self, incident_id: str, now: str, outcome: str) -> None:
        """Mark the token used (kept until TTL so MergeInvestigations can read started_at) and drop
        it from the live set. A token item that is already gone is not re-created."""
        try:
            self._table.update_item(Key={"pk": f"{TOKEN_PREFIX}{incident_id}"},
                                    UpdateExpression="SET consumed_at = :now, outcome = :o",
                                    ConditionExpression="attribute_exists(pk)",
                                    ExpressionAttributeValues={":now": now, ":o": outcome})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
        self._table.update_item(Key={"pk": LIVE_PK}, UpdateExpression="DELETE incident_ids :i",
                                ExpressionAttributeValues={":i": {incident_id}})

    def live_incident_ids(self) -> list[str]:
        item = self._table.get_item(Key={"pk": LIVE_PK}, ConsistentRead=True).get("Item") or {}
        return sorted(item.get("incident_ids") or [])

    def put_run(self, run_id: str, record: dict[str, Any], now: str) -> None:
        ttl = int((dt.datetime.fromisoformat(now.replace("Z", "+00:00")) + dt.timedelta(days=RUN_TTL_DAYS))
                  .timestamp())
        self._table.put_item(Item={"pk": f"RUN#{run_id}", **record, "ttl": ttl})
