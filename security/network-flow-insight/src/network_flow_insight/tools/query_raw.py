# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: validated SELECT against the raw flow-log table, always gauged."""

from __future__ import annotations

from ..core import s3layout
from ..core.athena import GaugedEngine
from ..core.sqlsafe import SqlPolicy, WindowBound
from ..core.tablescheme import TableScheme
from .run_athena import run_athena


def query_raw(
    sql: str,
    scheme: TableScheme,
    engine: GaugedEngine,
    log_inventory: s3layout.LogInventory,
    first_day: str,
    last_day: str,
    *,
    max_limit: int = 1000,
) -> dict:
    """The estimate is the full window's bytes. The gate therefore accepts only a statement whose literal start and
    end dates lie inside that window, so the scan cannot exceed what was estimated."""
    policy = SqlPolicy(
        {scheme.table: scheme.partition_cols},
        max_limit=max_limit,
        qualify={scheme.table: scheme.database},
        window=WindowBound(scheme.day_kind, first_day, last_day),
    )
    est = s3layout.estimate_bytes(log_inventory, first_day, last_day)
    out = run_athena(sql, policy, engine, estimated_bytes=est, label="raw query", max_rows=max_limit)
    out["source"] = "raw"
    return out
