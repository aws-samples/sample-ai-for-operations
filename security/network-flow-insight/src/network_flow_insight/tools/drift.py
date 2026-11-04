# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: compare observed conversations with a committed intent baseline.

A baseline entry covers a (consumer, provider, port). Path is compared separately: a covered key whose
observed paths include one the baseline never recorded is a path change. The baseline is never modified.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.intent_schema import Intent
from .enrich_conversations import provider_key


def _entry_key(e) -> tuple:
    p = e.provider
    if p.service:
        prov = ("aws-service", p.service)
    elif p.network:
        prov = (p.bucket or "named-network", p.network)
    else:
        prov = (p.bucket or "other-internet", p.cidr or "")
    return (e.consumer.network or "", prov, p.port)


def observed_index(enriched: list[dict]) -> dict[tuple, dict]:
    idx: dict[tuple, dict] = defaultdict(
        lambda: {"bytes": 0, "conversations": 0, "paths": defaultdict(int), "workloads": set()}
    )
    for c in enriched:
        if not c.get("egress") or c["action"] != "ACCEPT" or c["path_class"] in ("no-data", "rejected"):
            continue
        k = (c["consumer"], tuple(c["provider"]), c["port"])
        o = idx[k]
        o["bytes"] += c["total_bytes"]
        o["conversations"] += 1
        o["paths"][c["path_class"]] += c["total_bytes"]
        o["workloads"].add(c["client"])
    return idx


def drift(enriched: list[dict], intent: Intent) -> dict:
    if not intent.baseline:
        return {
            "error": "no committed baseline; describe mode applies. A baseline can be drafted from this run."
        }
    base: dict[tuple, dict] = defaultdict(lambda: {"paths": set(), "entries": 0, "evidence_bytes": 0})
    for e in intent.baseline:
        b = base[_entry_key(e)]
        b["paths"].add(e.provider.path)
        b["entries"] += 1
        b["evidence_bytes"] += e.evidence.bytes
    obs = observed_index(enriched)
    matched, new, stale, changed = [], [], [], []
    for k, o in sorted(obs.items(), key=lambda kv: (-kv[1]["bytes"], str(kv[0]))):
        item = {
            "consumer": k[0],
            "provider": list(k[1]),
            "port": k[2],
            "bytes": o["bytes"],
            "conversations": o["conversations"],
            "observed_paths": dict(sorted(o["paths"].items())),
            "workloads": sorted(o["workloads"]),
        }
        if k not in base:
            new.append(item)
            continue
        new_paths = sorted(set(o["paths"]) - base[k]["paths"])
        if new_paths:
            changed.append(
                {
                    **item,
                    "baseline_paths": sorted(base[k]["paths"]),
                    "new_paths": new_paths,
                    "bytes_on_new_paths": sum(o["paths"][p] for p in new_paths),
                }
            )
        else:
            matched.append({**item, "baseline_paths": sorted(base[k]["paths"])})
    for k, b in sorted(base.items(), key=lambda kv: str(kv[0])):
        if k not in obs:
            stale.append(
                {
                    "consumer": k[0],
                    "provider": list(k[1]),
                    "port": k[2],
                    "baseline_paths": sorted(b["paths"]),
                    "baseline_evidence_bytes": b["evidence_bytes"],
                }
            )
    return {
        "matched": matched,
        "path_changed": changed,
        "new": new,
        "stale": stale,
        "counts": {
            "matched": len(matched),
            "path_changed": len(changed),
            "new": len(new),
            "stale": len(stale),
        },
        "baseline_modified": False,
    }


__all__ = ["drift", "observed_index", "provider_key"]
