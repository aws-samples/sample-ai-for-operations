# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: sum measures by any set of dimensions."""

from __future__ import annotations

from collections import defaultdict

from ._common import n, share


def aggregate_by(
    rows: list[dict],
    dims: list[str],
    measures: list[str] | None = None,
    *,
    filters: dict[str, object] | None = None,
    counted_only: bool = True,
) -> dict:
    """Group ``rows`` by ``dims`` and sum ``measures`` (default ``bytes``, ``packets``, ``records``).

    ``filters`` keeps rows whose column equals the value (or is in the list). ``counted_only`` drops
    rows flagged ``counted = False`` (re-observations on forwarding interfaces) when the flag exists.
    """
    measures = measures or ["bytes", "packets", "records"]
    groups: dict[tuple, dict[str, int]] = defaultdict(lambda: dict.fromkeys(measures, 0))
    total = dict.fromkeys(measures, 0)
    for r in rows:
        if counted_only and not r.get("counted", True):
            continue
        if filters and not all(
            (r.get(k) in v) if isinstance(v, list | tuple | set) else (r.get(k) == v)
            for k, v in filters.items()
        ):
            continue
        key = tuple(r.get(d) for d in dims)
        for m in measures:
            v = n(r.get(m))
            groups[key][m] += v
            total[m] += v
    primary = measures[0]
    out = []
    for key, vals in sorted(groups.items(), key=lambda kv: (-kv[1][primary], tuple(str(x) for x in kv[0]))):
        row = dict(zip(dims, key, strict=True))
        row.update(vals)
        row[f"{primary}_share_pct"] = share(vals[primary], total[primary])
        out.append(row)
    return {"dims": dims, "measures": measures, "rows": out, "total": total, "groups": len(out)}
