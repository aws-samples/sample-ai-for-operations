# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: format_digest.

Groups DIGEST-disposition events since the last watermark by event family
(service + eventTypeCode) and account, producing both a plain-text digest and
a structured JSON representation. Pure code — no model call.

An "event family" groups events that share the same service and
eventTypeCode, since a single AWS maintenance wave typically produces many
account-specific messages for the same underlying change.
"""

from __future__ import annotations


def _family_key(event: dict) -> str:
    return f"{event.get('service', 'unknown')}::{event.get('eventTypeCode', 'unknown')}"


def _account_summary(event: dict) -> list[dict]:
    accounts = event.get("affectedAccounts", [])
    return accounts if isinstance(accounts, list) else []


def format_digest(events: list[dict], since: str | None = None) -> dict:
    """Format a list of DIGEST-disposition events into a digest.

    Args:
        events: List of consolidated event dicts (each expected to carry at
            least eventArn, service, eventTypeCode, eventTypeCategory,
            statusCode, affectedAccounts, and optionally classification,
            deadline, precheckResult).
        since: ISO 8601 timestamp of the previous digest watermark, included
            in the digest header for operator context.

    Returns:
        Dict with keys:
          - since: the watermark passed in (or None)
          - generated_at_event_count: total events included
          - families: list of {family_key, service, event_type_code, events,
            account_count, precheck_results} grouped entries
          - text: a plain-text rendering suitable for email/chat
          - included_event_arns: list of every eventArn included (for the
            audit record)
    """
    if not events:
        return {
            "since": since,
            "generated_at_event_count": 0,
            "families": [],
            "text": "AWS Health Digest\n\nNo digest-disposition events since the last run.",
            "included_event_arns": [],
        }

    families: dict[str, dict] = {}
    included_arns: list[str] = []

    for event in events:
        key = _family_key(event)
        included_arns.append(event.get("eventArn", ""))

        if key not in families:
            families[key] = {
                "family_key": key,
                "service": event.get("service", "unknown"),
                "event_type_code": event.get("eventTypeCode", "unknown"),
                "events": [],
                "account_ids": set(),
                "precheck_results": [],
            }

        bucket = families[key]
        bucket["events"].append({
            "eventArn": event.get("eventArn", ""),
            "statusCode": event.get("statusCode", ""),
            "deadline": event.get("deadline"),
            "classification": event.get("classification"),
        })
        bucket["account_ids"].update(_account_summary(event))

        precheck_result = event.get("precheckResult")
        if precheck_result:
            bucket["precheck_results"].append({
                "eventArn": event.get("eventArn", ""),
                "result": precheck_result.get("result"),
                "reason": precheck_result.get("reason"),
            })

    # Finalise family entries: convert account_ids set to count + sorted list
    family_list: list[dict] = []
    for bucket in families.values():
        family_list.append({
            "family_key": bucket["family_key"],
            "service": bucket["service"],
            "event_type_code": bucket["event_type_code"],
            "events": bucket["events"],
            "account_count": len(bucket["account_ids"]),
            "account_ids": sorted(bucket["account_ids"]),
            "precheck_results": bucket["precheck_results"],
        })

    # Sort families deterministically by family_key for stable digest output
    family_list.sort(key=lambda f: f["family_key"])

    text_lines = ["AWS Health Digest"]
    if since:
        text_lines.append(f"Events since: {since}")
    text_lines.append("")

    for fam in family_list:
        text_lines.append(f"[{fam['service']}] {fam['event_type_code']}")
        text_lines.append(f"  {len(fam['events'])} event(s) across {fam['account_count']} account(s)")
        for pr in fam["precheck_results"]:
            marker = "⚠️ " if pr["result"] == "fail" else ("❓ " if pr["result"] == "not_checked" else "")
            text_lines.append(f"  {marker}Precheck ({pr['eventArn'][:40]}...): {pr['result']}"
                               + (f" — {pr['reason']}" if pr.get("reason") else ""))
        text_lines.append("")

    return {
        "since": since,
        "generated_at_event_count": len(events),
        "families": family_list,
        "text": "\n".join(text_lines).rstrip(),
        "included_event_arns": included_arns,
    }
