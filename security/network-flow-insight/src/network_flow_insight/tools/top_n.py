# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: rank a table and give each entry's share of the total."""

from __future__ import annotations

from ._common import n, share


def top_n(table: list[dict], n_top: int, by: str = "bytes") -> dict:
    ranked = sorted(
        table, key=lambda r: (-n(r.get(by)), str(sorted((k, str(v)) for k, v in r.items() if k != by)))
    )
    total = sum(n(r.get(by)) for r in table)
    top = ranked[: max(n_top, 0)]
    rows = [
        {**r, "rank": i + 1, f"{by}_share_of_total_pct": share(n(r.get(by)), total)}
        for i, r in enumerate(top)
    ]
    shown = sum(n(r.get(by)) for r in top)
    return {
        "by": by,
        "n": n_top,
        "rows": rows,
        "total": total,
        "shown": shown,
        "others": total - shown,
        "others_share_pct": share(total - shown, total),
        "entries": len(table),
    }
