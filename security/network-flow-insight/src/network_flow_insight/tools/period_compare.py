# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: compare two equal windows."""

from __future__ import annotations

from ._common import n, share


def period_compare(
    current: list[dict], previous: list[dict], dims: list[str], measure: str = "bytes"
) -> dict:
    cur = {tuple(r.get(d) for d in dims): n(r.get(measure)) for r in current}
    prev = {tuple(r.get(d) for d in dims): n(r.get(measure)) for r in previous}
    keys = sorted(set(cur) | set(prev), key=lambda k: tuple(str(x) for x in k))
    rows = []
    for k in keys:
        c, p = cur.get(k, 0), prev.get(k, 0)
        status = (
            "new"
            if k not in prev
            else "gone"
            if k not in cur
            else "increased"
            if c > p
            else "decreased"
            if c < p
            else "unchanged"
        )
        rows.append(
            {
                **dict(zip(dims, k, strict=True)),
                "current": c,
                "previous": p,
                "delta": c - p,
                "change_pct": share(c - p, p) if p else None,
                "status": status,
            }
        )
    total_c, total_p = sum(cur.values()), sum(prev.values())
    growth = sum(r["delta"] for r in rows if r["delta"] > 0)
    for r in rows:
        r["share_of_growth_pct"] = share(r["delta"], growth) if r["delta"] > 0 else 0.0 if growth else None
    rows.sort(key=lambda r: (-abs(r["delta"]), tuple(str(r[d]) for d in dims)))
    return {
        "dims": dims,
        "measure": measure,
        "rows": rows,
        "totals": {
            "current": total_c,
            "previous": total_p,
            "delta": total_c - total_p,
            "change_pct": share(total_c - total_p, total_p),
        },
        "gross_growth": growth,
        "new": [r for r in rows if r["status"] == "new"],
        "gone": [r for r in rows if r["status"] == "gone"],
    }
