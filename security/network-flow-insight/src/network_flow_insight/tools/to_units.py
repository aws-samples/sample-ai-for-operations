# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: bytes to labelled decimal units."""

from __future__ import annotations

from ..core.units import to_units as _to_units


def to_units(num_bytes: int) -> dict:
    """Convert bytes to decimal GB/TB (10^9, 10^12). Always labelled; never silent."""
    return _to_units(num_bytes)
