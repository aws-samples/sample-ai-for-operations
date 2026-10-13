# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Sink dispatcher — resolves the owning team and fans out to configured sinks.

Called from the workflow's NOTIFY step. Pure orchestration:
  1. resolve_team() to determine the owning team and its channels.
  2. should_close() to decide upsert vs close.
  3. SnsSink always runs (core, R11.1). JiraSink/SlackSink/TeamsSink run only
     when the resolved team's channels configure them (jiraProject,
     chatChannel with a Slack/Teams-shaped identifier).
  4. Aggregates per-sink results; a failure on one sink does not block the
     others (R11.4 — retry with backoff belongs to the caller/Lambda retry
     policy; this dispatcher records success/failure per sink for the
     caller to persist and alert on).

Never calls the LLM. Never raises past dispatch() — a sink construction or
call failure is captured per-sink in the results dict.
"""

from __future__ import annotations

import logging

from src.triage.lifecycle import should_close
from src.triage.routing import resolve_team

logger = logging.getLogger(__name__)


def dispatch(
    record: dict,
    payload: dict,
    ticket_refs: dict,
    *,
    sns_sink,
    jira_sink=None,
    slack_sink=None,
    teams_sink=None,
    routing_table=None,
) -> dict:
    """Resolve the team and dispatch to all applicable sinks.

    Args:
        record: The consolidated event record (for should_close and routing
            inputs: affectedEntities, statusCode, service, account contexts).
        payload: The NotificationPayload v1 dict to send to each sink.
        ticket_refs: Dict of sink_name -> prior ticket_ref from TicketMap
            (e.g. {"jira": {"ticket_id": ...}, "sns": {"message_id": ...}}).
        sns_sink: An SnsSink instance (always dispatched to — R11.1 core sink).
        jira_sink: Optional JiraSink instance.
        slack_sink: Optional SlackSink instance.
        teams_sink: Optional TeamsSink instance.
        routing_table: Optional routing table override for resolve_team.

    Returns:
        Dict with keys:
          - team: the resolved team dict (from resolve_team)
          - closed: bool, whether this dispatch closed the event
          - results: dict of sink_name -> sink result dict
          - new_ticket_refs: dict of sink_name -> updated ticket_ref (for TicketMap)
    """
    entities = list(record.get("affectedEntities", {}).values()) if isinstance(
        record.get("affectedEntities"), dict
    ) else (record.get("affectedEntities") or [])
    account_contexts = record.get("accountContexts", [])
    service = record.get("service", "")

    team = resolve_team(entities, account_contexts, service, routing_table=routing_table)
    payload_with_team = {**payload, "assignedTeam": team["team"]}

    closing = should_close(record)

    results: dict = {}
    new_ticket_refs: dict = {}

    sinks = {"sns": sns_sink}
    channels = team.get("channels", {})
    if jira_sink is not None and channels.get("jiraProject"):
        sinks["jira"] = jira_sink
    if slack_sink is not None and channels.get("chatChannel"):
        sinks["slack"] = slack_sink
    if teams_sink is not None and channels.get("chatChannel"):
        sinks["teams"] = teams_sink

    for name, sink in sinks.items():
        try:
            prior_ref = ticket_refs.get(name)
            if closing and prior_ref:
                result = sink.close(prior_ref)
                new_ticket_refs[name] = prior_ref
            else:
                result = sink.upsert(payload_with_team, prior_ref)
                new_ticket_refs[name] = result
            results[name] = result
        except Exception as exc:
            logger.error("Sink '%s' dispatch failed: %s", name, exc)
            results[name] = {"status": "failed", "error": str(exc)}

    return {
        "team": team,
        "closed": closing,
        "results": results,
        "new_ticket_refs": new_ticket_refs,
    }
