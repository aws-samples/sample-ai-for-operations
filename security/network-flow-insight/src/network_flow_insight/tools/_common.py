# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Helpers shared by the precision tools. Pure functions only."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

Row = dict[str, Any]

# Path classes that are reported as separate, non-additive views (they re-observe traffic that is
# counted elsewhere) and therefore never enter volume totals.
UNCOUNTED_CLASSES = frozenset(
    {
        "nat-translated-leg",
        "nat-untranslated-leg",
        "nat-unmatched",
        "nat-unsolicited-inbound",
        "forwarding-interface",
        "rejected",
        "no-data",
    }
)


def n(value: Any) -> int:
    """Integer view of a numeric cell (None -> 0)."""
    return int(value) if value is not None else 0


def counted_rows(rows: Iterable[Row]) -> list[Row]:
    """Rows that count towards volume totals. Rows without a ``counted`` flag are assumed to count."""
    return [r for r in rows if r.get("counted", True)]


def ok_rows(rows: Iterable[Row]) -> list[Row]:
    return [r for r in rows if r.get("log_status", "OK") == "OK" and r.get("srcaddr") is not None]


def net24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) + ".0/24" if len(parts) == 4 else ip


def share(part: int | float, whole: int | float, digits: int = 2) -> float | None:
    return round(part / whole * 100, digits) if whole else None


def label(value: Any) -> Any:
    return "unknown" if value is None else value
