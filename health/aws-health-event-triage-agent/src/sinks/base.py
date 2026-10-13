# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Sink interface — common contract for all notification/ticket sinks.

Every sink (SnsSink, JiraSink, SlackSink, TeamsSink) implements upsert() and
close() so the dispatcher (src/sinks/dispatcher.py) can treat them
uniformly. Pure orchestration — no reasoning, no model call.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Sink(ABC):
    """Common interface for notification/ticket sinks."""

    @abstractmethod
    def upsert(self, payload: dict, ticket_ref: dict | None) -> dict:
        """Create or update a ticket/notification for this payload's eventArn.

        Args:
            payload: The NotificationPayload v1 dict to send.
            ticket_ref: The prior ticket reference for this eventArn (from
                TicketMap), or None if this is the first notification.

        Returns:
            A sink-specific ticket_ref dict to persist in TicketMap
            (e.g. {"ticket_id": ..., "url": ...} for Jira,
            {"message_id": ...} for SNS, {"message_ts": ...} for Slack).
            Must include a 'status' key: "sent"|"created"|"updated"|"failed"|"skipped".
        """
        raise NotImplementedError

    @abstractmethod
    def close(self, ticket_ref: dict) -> dict:
        """Close/resolve the ticket referenced by ticket_ref.

        Args:
            ticket_ref: The ticket reference dict from a prior upsert() call.

        Returns:
            A result dict with a 'status' key: "closed"|"failed"|"skipped".
        """
        raise NotImplementedError
