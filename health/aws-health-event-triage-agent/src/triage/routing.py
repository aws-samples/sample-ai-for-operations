# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: resolve_team.

Deterministically resolves the owning team for a health event from a
configurable RoutingTable. Pure code — no model call, never raises.

Precedence (R10.1):
  1. TAG   — resource tag on an affected entity (most specific)
  2. ACCOUNT / OU — the affected account, then its OU path
  3. SERVICE — the AWS service code (event.service)
  4. DEFAULT — always present in the seed; used when nothing else matches

RoutingTable format (config/routing.example.json):
  [{"ruleType": "TAG"|"ACCOUNT"|"OU"|"SERVICE"|"DEFAULT", "key": str,
    "team": str, "snsTopicArn": str, "jiraProject": str, "chatChannel": str,
    "escalation": str}, ...]
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_ROUTING_PATH = Path(__file__).parents[2] / "config" / "routing.example.json"

_FALLBACK_TEAM = "Platform-Operations"

_routing_cache: list[dict] | None = None


def _load_routing_table() -> list[dict]:
    global _routing_cache
    if _routing_cache is not None:
        return _routing_cache
    path = Path(os.environ.get("ROUTING_TABLE_PATH", str(_DEFAULT_ROUTING_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        _routing_cache = data if isinstance(data, list) else []
        logger.info("Loaded %d routing rules from %s", len(_routing_cache), path)
    except FileNotFoundError:
        _routing_cache = []
    except Exception as exc:
        logger.warning("Could not load routing table from %s: %s", path, exc)
        _routing_cache = []
    return _routing_cache


def _rule_to_result(rule: dict, rule_type: str) -> dict:
    return {
        "team": rule.get("team", _FALLBACK_TEAM),
        "channels": {
            "snsTopicArn": rule.get("snsTopicArn"),
            "jiraProject": rule.get("jiraProject"),
            "chatChannel": rule.get("chatChannel"),
        },
        "escalation": rule.get("escalation"),
        "routing": rule_type,
    }


def resolve_team(
    entities: list[dict],
    account_contexts: list[dict],
    service: str,
    routing_table: list[dict] | None = None,
) -> dict:
    """Resolve the owning team for a health event.

    Args:
        entities: The event's affected entities (each may carry a 'tags' dict).
        account_contexts: Enriched account context dicts (account_id, ou_path).
        service: The AWS service code (event.service).
        routing_table: Optional list of routing rules. If None, loads from
            config/routing.example.json (or ROUTING_TABLE_PATH).

    Returns:
        Dict with keys: team, channels ({snsTopicArn, jiraProject, chatChannel}),
        escalation, routing ("tag" | "account" | "ou" | "service" | "default" | "fallback").
    """
    table = routing_table if routing_table is not None else _load_routing_table()

    rules_by_type: dict[str, list[dict]] = {}
    for rule in table:
        rules_by_type.setdefault(rule.get("ruleType", ""), []).append(rule)

    # 1. TAG — check affected entities' tags against TAG rules
    for entity in entities:
        tags = entity.get("tags", {})
        if not isinstance(tags, dict):
            continue
        for rule in rules_by_type.get("TAG", []):
            key = rule.get("key", "")
            if "=" in key:
                tag_key, tag_value = key.split("=", 1)
                if tags.get(tag_key) == tag_value:
                    return _rule_to_result(rule, "tag")

    # 2a. ACCOUNT — check affected accounts against ACCOUNT rules
    account_ids = {ctx.get("account_id", "") for ctx in account_contexts}
    for rule in rules_by_type.get("ACCOUNT", []):
        if rule.get("key", "") in account_ids:
            return _rule_to_result(rule, "account")

    # 2b. OU — check affected accounts' OU paths against OU rules
    ou_paths = {ctx.get("ou_path", "") for ctx in account_contexts}
    for rule in rules_by_type.get("OU", []):
        if rule.get("key", "") in ou_paths:
            return _rule_to_result(rule, "ou")

    # 3. SERVICE
    for rule in rules_by_type.get("SERVICE", []):
        if rule.get("key", "") == service:
            return _rule_to_result(rule, "service")

    # 4. DEFAULT
    default_rules = rules_by_type.get("DEFAULT", [])
    if default_rules:
        return _rule_to_result(default_rules[0], "default")

    # No DEFAULT rule present at all (malformed table) — hardcoded fallback
    return {
        "team": _FALLBACK_TEAM,
        "channels": {"snsTopicArn": None, "jiraProject": None, "chatChannel": None},
        "escalation": None,
        "routing": "fallback",
    }
