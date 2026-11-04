# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: draft an intent baseline from observed conversations.

One entry per (consumer, provider, port, path), with the evidence a human needs to prune it. The output
validates against ``core.intent_schema.Intent``.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.intent_schema import Intent
from .enrich_conversations import provider_endpoint


def draft_intent(
    enriched: list[dict], dest_by_server: dict[str, dict], existing: Intent | None = None
) -> dict:
    groups: dict[tuple, dict] = defaultdict(
        lambda: {"bytes": 0, "conversations": 0, "first_seen": None, "last_seen": None}
    )
    prov: dict[tuple, dict] = {}
    for c in enriched:
        if not c.get("egress") or c["action"] != "ACCEPT" or c["path_class"] in ("no-data", "rejected"):
            continue
        key = (c["consumer"], tuple(c["provider"]), c["port"], c["path_class"])
        g = groups[key]
        g["bytes"] += c["total_bytes"]
        g["conversations"] += 1
        g["first_seen"] = c["first_day"] if g["first_seen"] is None else min(g["first_seen"], c["first_day"])
        g["last_seen"] = c["last_day"] if g["last_seen"] is None else max(g["last_seen"], c["last_day"])
        prov[key] = provider_endpoint(
            dest_by_server.get(c["server"], {"bucket": "other-internet", "service": "", "name": ""}),
            c["server"],
        )
    entries = []
    for key, g in sorted(groups.items(), key=lambda kv: (-kv[1]["bytes"], str(kv[0]))):
        consumer, _prov, port, path = key
        entries.append(
            {
                "consumer": {"network": consumer},
                "provider": {**prov[key], "port": port, "path": path},
                "evidence": g,
            }
        )
    doc = {
        "version": 1,
        "networks": [n.model_dump() for n in existing.networks] if existing else [],
        "buckets": [b.model_dump() for b in existing.buckets] if existing else [],
        "baseline": entries,
    }
    Intent.model_validate(doc)  # fail loudly if the draft would not load back
    return doc
