# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Cloud WAN core network policy evaluation helpers (precision code).

Implements the subset of policy semantics the checks need:
- attachment-policies: rule-number order, first match wins, conditions with and/or logic,
  association-method constant | tag.
- segment-actions: share (attachment-route mode, '*' / list / {'except': [...]}) and create-route.
"""

from __future__ import annotations

from typing import Any

# ListAttachments AttachmentType -> policy 'attachment-type' condition value
ATTACHMENT_TYPE_TO_POLICY = {
    "VPC": "vpc",
    "CONNECT": "connect",
    "SITE_TO_SITE_VPN": "site-to-site-vpn",
    "TRANSIT_GATEWAY_ROUTE_TABLE": "transit-gateway-route-table",
    "DIRECT_CONNECT_GATEWAY": "direct-connect-gateway",
}

UNSUPPORTED = object()  # sentinel: rule uses a construct we do not evaluate


def _match_operator(operator: str, actual: str | None, expected: str) -> bool | object:
    if actual is None:
        return False
    op = (operator or "equals").lower()
    if op == "equals":
        return actual == expected
    if op == "not-equals":
        return actual != expected
    if op == "contains":
        return expected in actual
    if op == "begins-with":
        return actual.startswith(expected)
    return UNSUPPORTED


def _condition(cond: dict[str, Any], att: dict[str, Any]) -> bool | object:
    ctype = (cond.get("type") or "").lower()
    tags: dict[str, str] = att.get("tags") or {}
    if ctype == "any":
        return True
    if ctype == "tag-exists":
        return cond.get("key") in tags
    operator = cond.get("operator", "equals")
    expected = str(cond.get("value", ""))
    if ctype == "tag-value":
        return _match_operator(operator, tags.get(cond.get("key", "")), expected)
    if ctype == "resource-id":
        return _match_operator(operator, att.get("resource_id"), expected)
    if ctype == "region":
        return _match_operator(operator, att.get("edge_location"), expected)
    if ctype == "account-id":
        return _match_operator(operator, att.get("owner_account_id"), expected)
    if ctype == "attachment-type":
        raw_type = att.get("attachment_type") or ""
        actual = ATTACHMENT_TYPE_TO_POLICY.get(raw_type, raw_type.lower())
        return _match_operator(operator, actual, expected.lower())
    return UNSUPPORTED


def expected_segment(policy: dict[str, Any], att: dict[str, Any]) -> tuple[str, Any]:
    """Return (status, value) for the segment the policy would assign this attachment.

    status: 'segment' (value = segment name), 'no-match', 'nfg' (network function group,
    out of scope), or 'unsupported' (value = rule number using a construct we don't evaluate).
    """
    rules = sorted(policy.get("attachment-policies") or [], key=lambda r: r.get("rule-number", 0))
    for rule in rules:
        logic = (rule.get("condition-logic") or "and").lower()
        results = [_condition(c, att) for c in rule.get("conditions") or []]
        if any(r is UNSUPPORTED for r in results):
            return "unsupported", rule.get("rule-number")
        matched = any(results) if logic == "or" else all(results)
        if not matched:
            continue
        action = rule.get("action") or {}
        if action.get("add-to-network-function-group"):
            return "nfg", action.get("add-to-network-function-group")
        method = (action.get("association-method") or "").lower()
        if method == "constant":
            return "segment", action.get("segment")
        if method == "tag":
            value = (att.get("tags") or {}).get(action.get("tag-value-of-key", ""))
            return ("segment", value) if value else ("no-match", rule.get("rule-number"))
        return "unsupported", rule.get("rule-number")
    return "no-match", None


def _share_targets(action: dict[str, Any], all_segments: set[str]) -> set[str]:
    share_with = action.get("share-with")
    if share_with == "*":
        return set(all_segments)
    if isinstance(share_with, list):
        return {str(s).lower() for s in share_with}
    if isinstance(share_with, dict) and "except" in share_with:
        return set(all_segments) - {str(s).lower() for s in share_with["except"]}
    return set()


def _filter_allows(segment_def: dict[str, Any] | None, other: str) -> bool:
    """Apply a segment's deny-filter / allow-filter to routes from `other` (applied after sharing)."""
    if not segment_def:
        return True
    deny = {str(s).lower() for s in segment_def.get("deny-filter") or []}
    allow = segment_def.get("allow-filter")
    if other in deny:
        return False
    if allow is not None:
        return other in {str(s).lower() for s in allow}
    return True


def shared_pairs(policy: dict[str, Any]) -> set[frozenset[str]]:
    """Unordered segment pairs that exchange routes via a 'share' segment action, after each
    segment's deny-filter / allow-filter. A pair survives only if both sides' filters allow it."""
    defs = {str(s.get("name", "")).lower(): s for s in policy.get("segments") or [] if s.get("name")}
    segments = set(defs)
    pairs: set[frozenset[str]] = set()
    for action in policy.get("segment-actions") or []:
        if (action.get("action") or "").lower() != "share":
            continue
        mode = (action.get("mode") or "attachment-route").lower()
        if mode != "attachment-route":
            continue
        source = str(action.get("segment", "")).lower()
        for target in _share_targets(action, segments):
            if not target or target == source:
                continue
            if _filter_allows(defs.get(source), target) and _filter_allows(defs.get(target), source):
                pairs.add(frozenset((source, target)))
    return pairs


def isolated_segments(policy: dict[str, Any]) -> set[str]:
    """Segments with isolate-attachments: true (VPC attachments must not learn each other's routes)."""
    return {str(s.get("name", "")).lower() for s in policy.get("segments") or []
            if s.get("name") and s.get("isolate-attachments") is True}


def static_routes(policy: dict[str, Any]) -> set[tuple[str, str]]:
    """(segment, canonical cidr) pairs declared by 'create-route' segment actions."""
    from drift_core.finding import canonical_prefix

    result: set[tuple[str, str]] = set()
    for action in policy.get("segment-actions") or []:
        if (action.get("action") or "").lower() != "create-route":
            continue
        segment = str(action.get("segment", "")).lower()
        for cidr in action.get("destination-cidr-blocks") or []:
            result.add((segment, canonical_prefix(str(cidr))))
    return result
