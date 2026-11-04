# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: validated SELECT against the aggregate only (cheap)."""

from __future__ import annotations

from ..core.athena import GaugedEngine
from ..core.sqlsafe import SqlPolicy
from .run_athena import run_athena


def query_aggregate(
    sql: str,
    aggregate_tables: list[str],
    engine: GaugedEngine,
    *,
    aggregate_bytes: int,
    max_limit: int = 1000,
    database: str = "",
) -> dict:
    policy = SqlPolicy(
        {t: ("day",) for t in aggregate_tables},
        max_limit=max_limit,
        qualify={t: database for t in aggregate_tables} if database else {},
    )
    out = run_athena(
        sql, policy, engine, estimated_bytes=aggregate_bytes, label="aggregate query", max_rows=max_limit
    )
    out["source"] = "aggregate"
    return out
