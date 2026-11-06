# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: per-day series, weekday versus weekend, peak day and peak hour."""

from __future__ import annotations

from collections import defaultdict
from datetime import date

from ._common import counted_rows, n

WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def time_profile(rows: list[dict], days: list[str] | None = None) -> dict:
    per_day: dict[str, int] = defaultdict(int)
    per_day_hour: dict[tuple[str, int], int] = defaultdict(int)
    per_hour: dict[int, int] = defaultdict(int)
    for r in counted_rows(rows):
        b = n(r.get("bytes"))
        per_day[r["day"]] += b
        if r.get("hour") is not None:
            per_day_hour[(r["day"], int(r["hour"]))] += b
            per_hour[int(r["hour"])] += b
    for d in days or []:
        per_day.setdefault(d, 0)
    series = [
        {"day": d, "weekday": WEEKDAYS[date.fromisoformat(d).weekday()], "bytes": per_day[d]}
        for d in sorted(per_day)
    ]
    wk = [s["bytes"] for s in series if date.fromisoformat(s["day"]).weekday() < 5]
    we = [s["bytes"] for s in series if date.fromisoformat(s["day"]).weekday() >= 5]
    peak_day = max(series, key=lambda s: (s["bytes"], s["day"]), default=None)
    peak_dh = max(per_day_hour.items(), key=lambda kv: (kv[1], kv[0]), default=None)
    peak_h = max(per_hour.items(), key=lambda kv: (kv[1], -kv[0]), default=None)
    return {
        "series": series,
        "total_bytes": sum(per_day.values()),
        "weekday_mean_bytes": (sum(wk) // len(wk)) if wk else None,
        "weekend_mean_bytes": (sum(we) // len(we)) if we else None,
        "weekday_days": len(wk),
        "weekend_days": len(we),
        "peak_day": peak_day,
        "peak_hour_of_window": None
        if peak_dh is None
        else {"day": peak_dh[0][0], "hour": peak_dh[0][1], "bytes": peak_dh[1]},
        "peak_hour_of_day": None if peak_h is None else {"hour": peak_h[0], "bytes": peak_h[1]},
        "hourly_available": bool(per_hour),
    }
