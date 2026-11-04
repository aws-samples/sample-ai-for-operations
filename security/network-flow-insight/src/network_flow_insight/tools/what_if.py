# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: treat the committed baseline as enforced egress policy.

Reports the share of observed bytes and conversations that fall outside the baseline, by destination
bucket and by originating workload. Path is not part of the policy key: a covered destination reached
by a different path is still permitted (drift reports it).
"""

from __future__ import annotations

from collections import defaultdict

from ..core.intent_schema import Intent
from ._common import share
from .drift import _entry_key


def what_if(enriched: list[dict], intent: Intent) -> dict:
    if not intent.baseline:
        return {
            "error": "no committed baseline; describe mode applies. A baseline can be drafted from this run."
        }
    allowed = {_entry_key(e) for e in intent.baseline}
    total_b = total_c = deny_b = deny_c = 0
    by_bucket: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "conversations": 0})
    by_workload: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "conversations": 0})
    denied = []
    for c in enriched:
        if not c.get("egress") or c["action"] != "ACCEPT" or c["path_class"] in ("no-data", "rejected"):
            continue
        total_b += c["total_bytes"]
        total_c += 1
        if (c["consumer"], tuple(c["provider"]), c["port"]) in allowed:
            continue
        deny_b += c["total_bytes"]
        deny_c += 1
        bk = by_bucket[c["customer_bucket"] if c.get("customer_bucket") else c["dest_bucket"]]
        bk["bytes"] += c["total_bytes"]
        bk["conversations"] += 1
        wl = by_workload[c["client"]]
        wl["bytes"] += c["total_bytes"]
        wl["conversations"] += 1
        denied.append(
            {
                "client": c["client"],
                "server": c["server"],
                "port": c["port"],
                "bucket": c["dest_bucket"],
                "bytes": c["total_bytes"],
                "path_class": c["path_class"],
            }
        )
    return {
        "denied_bytes": deny_b,
        "total_bytes": total_b,
        "denied_bytes_share_pct": share(deny_b, total_b),
        "denied_conversations": deny_c,
        "total_conversations": total_c,
        "denied_conversations_share_pct": share(deny_c, total_c),
        "by_bucket": [
            {"bucket": k, **v, "bytes_share_of_denied_pct": share(v["bytes"], deny_b)}
            for k, v in sorted(by_bucket.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))
        ],
        "by_workload": [
            {"workload": k, **v, "bytes_share_of_denied_pct": share(v["bytes"], deny_b)}
            for k, v in sorted(by_workload.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))
        ],
        "denied": sorted(denied, key=lambda d: (-d["bytes"], d["client"], d["server"])),
    }
