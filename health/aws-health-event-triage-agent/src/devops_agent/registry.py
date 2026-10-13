# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
# Risk assessment: See SECURITY.md for threat model and risk documentation.

"""Precision tool: resolve_agent_space.

Deterministically resolves the target AWS DevOps Agent Agent Space for a
health event from a configurable AgentSpaceRegistry. Pure code — no model
call, no AWS call, never raises.

Precedence (R12.6):
  1. ACCOUNT + TAG — an affected account combined with a resource tag (most specific)
  2. ACCOUNT       — the affected account
  3. OU            — the affected account's OU path
  4. DEFAULT       — the organization default, if configured

Unmatched accounts with no DEFAULT rule SHALL NOT be investigated (R12.6) —
this function returns None in that case; callers must not fall back to a
hardcoded space.

AgentSpaceRegistry format (config/agent_space_registry.example.json):
  [{"ruleType": "ACCOUNT_TAG"|"ACCOUNT"|"OU"|"DEFAULT", "key": str,
    "agentSpaceId": str, "ownerAccountId": str, "region": str,
    "triggerMethod": "WEBHOOK"|"ASSUME_ROLE", "webhookUrl": str|None,
    "webhookSecretArn": str|None,
    "assumableRoleArn": str|None, "allowedScopes": list[str],
    "allowedAccountNotificationCodes": list[str],
    "incidentCapPerMonth": int, "readinessEnabled": bool,
    "readinessCapPerMonth": int, "dedupeWindowMinutes": int}, ...]
  readinessCapPerMonth (E4.5, Phase B feat-devops-agent-enrichment): still
  accepted in the schema and still read, but its old semantics — a SEPARATE
  per-month cap on standalone readiness investigations — are superseded now
  that a single enrichment investigation answers both impact and readiness.
  It no longer gates a distinct readiness-investigation path (that path was
  retired); readiness rides the single per-space incident cap. Kept in the
  schema (not removed) for backward compatibility; a deprecation log line is
  emitted where it is read (workflow_handler._decide_readiness_for_enrichment).

  webhookUrl (found missing from the shipped example this session, working
  spec feat-devops-agent-enrichment task 13): the Agent Space's eventChannel
  webhook endpoint URL. trigger_investigation_step()
  (src/devops_agent/workflow_handler.py) already reads
  registry_entry.get("webhookUrl", "") unconditionally — it is REQUIRED for
  triggerMethod: "WEBHOOK" to actually send anything (webhookSecretArn alone
  only supplies the HMAC signing secret, not the destination). A registry
  entry with triggerMethod: "WEBHOOK" and no webhookUrl degrades silently to
  posting to an empty URL rather than raising — see send_webhook()'s own URL
  validation for the resulting failure mode (a caught, logged send error,
  not a crash).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_REGISTRY_PATH = Path(__file__).parents[2] / "config" / "agent_space_registry.example.json"

_registry_cache: list[dict] | None = None


def _load_registry() -> list[dict]:
    global _registry_cache
    if _registry_cache is not None:
        return _registry_cache
    path = Path(os.environ.get("AGENT_SPACE_REGISTRY_PATH", str(_DEFAULT_REGISTRY_PATH)))
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        _registry_cache = data if isinstance(data, list) else []
        logger.info("Loaded %d Agent Space registry entries from %s", len(_registry_cache), path)
    except FileNotFoundError:
        _registry_cache = []
    except Exception as exc:
        logger.warning("Could not load Agent Space registry from %s: %s", path, exc)
        _registry_cache = []
    return _registry_cache


def _resolve_for_single_account(
    account_id: str,
    account_contexts: list[dict],
    rules_by_type: dict[str, list[dict]],
) -> dict | None:
    """Resolve the registry entry for exactly ONE account, using the same
    ACCOUNT_TAG -> ACCOUNT -> OU -> DEFAULT precedence as
    resolve_agent_space(), but scoped to a single account rather than the
    combined affected-accounts list. Internal helper for
    resolve_agent_spaces_by_account() (task 11, design §3.0)."""
    accounts_by_id = {ctx.get("account_id", ""): ctx for ctx in account_contexts}
    ctx = accounts_by_id.get(account_id, {})

    # 1. ACCOUNT_TAG
    for rule in rules_by_type.get("ACCOUNT_TAG", []):
        key = rule.get("key", "")
        if "=" not in key:
            continue
        tag_key, tag_value = key.split("=", 1)
        tags = ctx.get("tags", {})
        if isinstance(tags, dict) and tags.get(tag_key) == tag_value:
            return rule

    # 2. ACCOUNT
    for rule in rules_by_type.get("ACCOUNT", []):
        if rule.get("key", "") == account_id:
            return rule

    # 3. OU
    ou_path = ctx.get("ou_path", "")
    if ou_path:
        for rule in rules_by_type.get("OU", []):
            if rule.get("key", "") == ou_path:
                return rule

    # 4. DEFAULT
    default_rules = rules_by_type.get("DEFAULT", [])
    if default_rules:
        return default_rules[0]

    return None


def resolve_agent_space(
    affected_accounts: list[str],
    account_contexts: list[dict],
    registry: list[dict] | None = None,
) -> dict | None:
    """Resolve the target Agent Space registry entry for a health event.

    Args:
        affected_accounts: Account IDs the event affects (from
            health_event_v1 affectedAccount / affectedAccounts).
        account_contexts: Enriched account context dicts (account_id,
            ou_path, tags) from the Phase 1 account-context enrichment.
        registry: Optional list of registry entries. If None, loads from
            config/agent_space_registry.example.json (or
            AGENT_SPACE_REGISTRY_PATH).

    Returns:
        The matching registry entry dict, or None if no ACCOUNT_TAG,
        ACCOUNT, or OU rule matches and no DEFAULT rule is configured.
    """
    table = registry if registry is not None else _load_registry()

    rules_by_type: dict[str, list[dict]] = {}
    for rule in table:
        rules_by_type.setdefault(rule.get("ruleType", ""), [])
        rules_by_type[rule.get("ruleType", "")].append(rule)

    accounts_by_id = {ctx.get("account_id", ""): ctx for ctx in account_contexts}

    # 1. ACCOUNT_TAG — an affected account whose context carries a matching tag
    for rule in rules_by_type.get("ACCOUNT_TAG", []):
        key = rule.get("key", "")
        if "=" not in key:
            continue
        tag_key, tag_value = key.split("=", 1)
        for account_id in affected_accounts:
            ctx = accounts_by_id.get(account_id, {})
            tags = ctx.get("tags", {})
            if isinstance(tags, dict) and tags.get(tag_key) == tag_value:
                return rule

    # 2. ACCOUNT — an affected account matches directly
    for rule in rules_by_type.get("ACCOUNT", []):
        if rule.get("key", "") in affected_accounts:
            return rule

    # 3. OU — an affected account's OU path matches
    ou_paths = {
        accounts_by_id.get(account_id, {}).get("ou_path", "")
        for account_id in affected_accounts
    }
    ou_paths.discard("")
    for rule in rules_by_type.get("OU", []):
        if rule.get("key", "") in ou_paths:
            return rule

    # 4. DEFAULT
    default_rules = rules_by_type.get("DEFAULT", [])
    if default_rules:
        return default_rules[0]

    return None


def resolve_agent_spaces_by_account(
    affected_accounts: list[str],
    account_contexts: list[dict],
    registry: list[dict] | None = None,
) -> list[dict]:
    """Resolve the target Agent Space registry entry PER account, then
    group accounts by the distinct space each one resolves to.

    Added task 11, working spec feat-devops-agent-enrichment, design §3.0:
    "Where they span spaces → gate.py iterates the distinct spaces." This
    is genuinely different from resolve_agent_space() above (which
    resolves ONE entry for the whole affected_accounts list combined,
    stopping at the first ACCOUNT_TAG/ACCOUNT/OU/DEFAULT match across ALL
    accounts together) — that function cannot tell two accounts belonging
    to different BU spaces apart; this one can, because it runs the same
    precedence rule independently for each account.

    Args:
        affected_accounts: Account IDs the event affects.
        account_contexts: Enriched account context dicts (account_id,
            ou_path, tags).
        registry: Optional list of registry entries. If None, loads from
            the same source resolve_agent_space() uses.

    Returns:
        A list of {"agentSpaceEntry": dict, "accounts": list[str]} dicts,
        one per DISTINCT resolved space, each carrying every account that
        resolved to it (sorted, for deterministic test assertions).
        Accounts that resolve to no space at all (no ACCOUNT_TAG/ACCOUNT/OU
        match and no DEFAULT configured) are grouped separately under a
        single {"agentSpaceEntry": None, "accounts": [...]} entry, always
        last in the returned list, so a caller can see uncovered accounts
        without a separate lookup (E1.5 cause 1 — "no Agent Space registry
        entry matches account <id>"). Empty affected_accounts returns [].
    """
    table = registry if registry is not None else _load_registry()

    rules_by_type: dict[str, list[dict]] = {}
    for rule in table:
        rules_by_type.setdefault(rule.get("ruleType", ""), [])
        rules_by_type[rule.get("ruleType", "")].append(rule)

    # Group by agentSpaceId (a rule's identity for grouping purposes) so
    # two different registry rules that happen to point at the same
    # Agent Space still merge into one Map branch — the design's whole
    # point is "one investigation per DISTINCT SPACE," not per rule.
    groups: dict[str, dict] = {}
    uncovered_accounts: list[str] = []

    for account_id in affected_accounts:
        entry = _resolve_for_single_account(account_id, account_contexts, rules_by_type)
        if entry is None:
            uncovered_accounts.append(account_id)
            continue
        space_id = entry.get("agentSpaceId", "")
        group = groups.setdefault(space_id, {"agentSpaceEntry": entry, "accounts": []})
        group["accounts"].append(account_id)

    result = [
        {"agentSpaceEntry": g["agentSpaceEntry"], "accounts": sorted(g["accounts"])}
        for g in groups.values()
    ]
    # Deterministic order across calls: sort by agentSpaceId.
    result.sort(key=lambda g: g["agentSpaceEntry"].get("agentSpaceId", ""))

    if uncovered_accounts:
        result.append({"agentSpaceEntry": None, "accounts": sorted(uncovered_accounts)})

    return result
