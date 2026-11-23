# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""AgentCore Memory adapter for shared, structured assessment state.

Conversational memory is handled separately by the Strands session manager.
This adapter stores exact answer records as synchronous blob events so the
scoring engine never depends on an asynchronously generated summary.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, Protocol

from src.assessment_core import SessionStoreError
from src.config import AppSettings
from src.questions import QUESTION_CATALOG_VERSION
from src.session_store import SessionAnswer, SessionStore

SCHEMA_VERSION = 2
MAX_EVENTS = 1_000


class MemoryClientProtocol(Protocol):
    """Subset of the AgentCore Memory client used by this adapter."""

    def create_blob_event(
        self,
        memory_id: str,
        actor_id: str,
        session_id: str,
        blob_data: Any,
        event_timestamp: datetime | None = None,
        branch: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def list_events(
        self,
        memory_id: str,
        actor_id: str,
        session_id: str,
        branch_name: str | None = None,
        include_parent_branches: bool = False,
        event_metadata: list[Any] | None = None,
        max_results: int = 100,
        include_payload: bool = True,
    ) -> list[dict[str, Any]]: ...


class SanitizerProtocol(Protocol):
    """Structural type implemented by assessment_core.Redactor."""

    def sanitize(self, value: Any) -> Any: ...


class AgentCoreSessionStoreError(SessionStoreError):
    """Raised when shared assessment state cannot be read or persisted."""


class AgentCoreMemorySessionStore(SessionStore):
    """Append-only AgentCore Memory implementation of ``SessionStore``."""

    def __init__(
        self,
        settings: AppSettings,
        redactor: SanitizerProtocol,
        client: MemoryClientProtocol | None = None,
    ) -> None:
        settings.validate()
        if settings.session_profile != "v2" or not settings.agentcore_memory_id:
            raise AgentCoreSessionStoreError(
                "AgentCoreMemorySessionStore requires a complete v2 profile."
            )

        self._settings = settings
        self._redactor = redactor
        self._client = client or self._new_client(settings.agentcore_region)

    @staticmethod
    def _new_client(region: str) -> MemoryClientProtocol:
        """Import the SDK lazily so v1 never constructs an AgentCore client."""

        try:
            from bedrock_agentcore.memory import MemoryClient
        except ImportError as exc:  # pragma: no cover - installation failure
            raise AgentCoreSessionStoreError(
                "The bedrock-agentcore package is required for profile v2."
            ) from exc
        return MemoryClient(region_name=region)

    def list_answers(self) -> tuple[SessionAnswer, ...]:
        """Fold the shared event stream into the latest answer per question."""

        records = self._read_records()
        latest: dict[str, SessionAnswer] = {}
        for _, record in records:
            if record.get("record_type") != "answer":
                continue
            question_id = str(record.get("question_id", "")).strip()
            answer_value = str(record.get("answer_value", "")).strip()
            if not question_id or not answer_value:
                continue
            latest[question_id] = SessionAnswer(
                question_id=question_id,
                answer_value=answer_value,
                source=str(record.get("source", "agentcore-memory")),
                timestamp=str(record.get("timestamp", "")),
                changed=bool(record.get("changed", False)),
            )
        return tuple(latest[question_id] for question_id in sorted(latest))

    def set_answer(
        self, question_id: str, answer_value: str, source: str = "agent"
    ) -> SessionAnswer:
        """Append one redacted answer and return the canonical stored record."""

        normalized_id = question_id.strip().upper()
        if not normalized_id.startswith("BQ-"):
            raise AgentCoreSessionStoreError(
                "Only canonical BQ-* question IDs can be persisted."
            )

        sanitized_value = str(self._redactor.sanitize(answer_value)).strip()
        if not sanitized_value:
            raise AgentCoreSessionStoreError("Answer value cannot be empty.")

        previous = {answer.question_id: answer for answer in self.list_answers()}.get(
            normalized_id
        )
        timestamp = datetime.now(UTC).isoformat()
        answer = SessionAnswer(
            question_id=normalized_id,
            answer_value=sanitized_value,
            source=str(self._redactor.sanitize(source)).strip() or "agent",
            timestamp=timestamp,
            changed=bool(previous and previous.answer_value != sanitized_value),
        )
        self._append_record(
            {
                "schema_version": SCHEMA_VERSION,
                "catalog_version": QUESTION_CATALOG_VERSION,
                "record_type": "answer",
                "assessment_id": self._settings.assessment_id,
                "contributor_id": self._settings.contributor_id,
                **asdict(answer),
            }
        )
        return answer

    def as_business_context_answers(self) -> tuple[dict[str, object], ...]:
        """Return the payload shape consumed by deterministic scoring."""

        return tuple(asdict(answer) for answer in self.list_answers())

    def mark_derived_current(self, assessment_id: str) -> None:
        """Append a marker after all requested report artifacts are written."""

        self._append_record(
            {
                "schema_version": SCHEMA_VERSION,
                "catalog_version": QUESTION_CATALOG_VERSION,
                "record_type": "derived_current",
                "assessment_id": assessment_id,
                "contributor_id": self._settings.contributor_id,
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    def _append_record(self, record: Mapping[str, Any]) -> None:
        memory_id = self._settings.agentcore_memory_id
        if memory_id is None:  # guarded by __init__, keeps mypy honest
            raise AgentCoreSessionStoreError("AGENTCORE_MEMORY_ID is required.")

        # AgentCore accepts dictionaries as blob payloads. Metadata lets
        # operators distinguish assessment state from Strands chat events.
        try:
            self._client.create_blob_event(
                memory_id=memory_id,
                actor_id=self._settings.memory_actor_id,
                session_id=self._settings.memory_session_id,
                blob_data=json.dumps(
                    dict(record),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                event_timestamp=datetime.now(UTC),
                metadata={
                    "recordType": {
                        "stringValue": str(record.get("record_type", "unknown"))
                    },
                    "assessmentId": {
                        "stringValue": self._settings.assessment_id
                    },
                },
            )
        except Exception as exc:
            raise AgentCoreSessionStoreError(
                "Could not persist shared assessment state in AgentCore Memory."
            ) from exc

    def _read_records(self) -> list[tuple[tuple[float, str], dict[str, Any]]]:
        memory_id = self._settings.agentcore_memory_id
        if memory_id is None:  # guarded by __init__, keeps mypy honest
            raise AgentCoreSessionStoreError("AGENTCORE_MEMORY_ID is required.")

        try:
            events = self._client.list_events(
                memory_id=memory_id,
                actor_id=self._settings.memory_actor_id,
                session_id=self._settings.memory_session_id,
                max_results=MAX_EVENTS,
                include_payload=True,
            )
        except Exception as exc:
            raise AgentCoreSessionStoreError(
                "Could not load shared assessment state from AgentCore Memory."
            ) from exc

        records: list[tuple[tuple[float, str], dict[str, Any]]] = []
        for raw_event in events:
            event = self._unwrap_event(raw_event)
            record = self._extract_record(event)
            if record is None or record.get("assessment_id") != self._settings.assessment_id:
                continue
            if record.get("schema_version") != SCHEMA_VERSION:
                continue
            records.append((self._event_sort_key(event, record), record))
        records.sort(key=lambda item: item[0])
        return records

    @staticmethod
    def _unwrap_event(value: Mapping[str, Any]) -> Mapping[str, Any]:
        nested = value.get("event")
        return nested if isinstance(nested, Mapping) else value

    @staticmethod
    def _extract_record(event: Mapping[str, Any]) -> dict[str, Any] | None:
        payload = event.get("payload")
        if not isinstance(payload, list):
            return None
        for item in payload:
            if not isinstance(item, Mapping) or "blob" not in item:
                continue
            blob = item["blob"]
            if isinstance(blob, Mapping):
                return dict(blob)
            if isinstance(blob, bytes):
                blob = blob.decode("utf-8")
            if isinstance(blob, str):
                try:
                    parsed = json.loads(blob)
                except json.JSONDecodeError:
                    return None
                return dict(parsed) if isinstance(parsed, Mapping) else None
        return None

    @staticmethod
    def _event_sort_key(
        event: Mapping[str, Any], record: Mapping[str, Any]
    ) -> tuple[float, str]:
        raw_timestamp = event.get("eventTimestamp", record.get("timestamp", ""))
        if isinstance(raw_timestamp, datetime):
            timestamp = raw_timestamp.timestamp()
        elif isinstance(raw_timestamp, int | float):
            timestamp = float(raw_timestamp)
        else:
            try:
                timestamp = datetime.fromisoformat(
                    str(raw_timestamp).replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                timestamp = 0.0
        return timestamp, str(event.get("eventId", ""))
