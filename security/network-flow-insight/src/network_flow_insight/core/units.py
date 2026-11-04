# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Byte formatting. Everything is computed in bytes and reported in decimal units, labelled."""

from __future__ import annotations

_UNITS = ("B", "KB", "MB", "GB", "TB", "PB")


def to_units(num_bytes: int | float | None) -> dict:
    """Return ``{bytes, value, unit, text}`` using decimal (10^3) units, never silently."""
    if num_bytes is None:
        return {"bytes": None, "value": None, "unit": None, "text": "n/a"}
    n = float(num_bytes)
    sign = -1 if n < 0 else 1
    n = abs(n)
    idx = 0
    while n >= 1000 and idx < len(_UNITS) - 1:
        n /= 1000
        idx += 1
    value = round(sign * n, 2) if idx else sign * int(n)
    unit = _UNITS[idx]
    return {"bytes": int(num_bytes), "value": value, "unit": unit, "text": f"{value} {unit}"}


def fmt_bytes(num_bytes: int | float | None) -> str:
    return to_units(num_bytes)["text"]


def ratio(numerator: float, denominator: float) -> float | None:
    """Plain division that returns None instead of raising on a zero denominator."""
    return None if not denominator else numerator / denominator


def pct(part: float, whole: float, digits: int = 2) -> float | None:
    r = ratio(part, whole)
    return None if r is None else round(r * 100, digits)
