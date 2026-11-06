# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: validate, gauge and run one SELECT; capture the execution ID and bytes scanned."""

from __future__ import annotations

from ..core.athena import GaugedEngine, QuerySkipped
from ..core.sqlsafe import SqlPolicy, SqlRejected, validate


def run_athena(
    sql: str,
    policy: SqlPolicy,
    engine: GaugedEngine,
    *,
    estimated_bytes: int,
    label: str = "",
    max_rows: int = 1000,
) -> dict:
    try:
        safe = validate(sql, policy)
    except SqlRejected as exc:
        return {"status": "rejected", "reason": str(exc), "executed": False}
    try:
        res = engine.run(safe, estimated_bytes=estimated_bytes, label=label, max_rows=max_rows)
    except QuerySkipped as exc:
        return {"status": "skipped", "reason": str(exc), "executed": False, "sql": safe}
    return {
        "status": "ok",
        "executed": True,
        "sql": safe,
        "columns": res.columns,
        "rows": res.rows,
        "row_count": len(res.rows),
        "truncated": res.truncated,
        "execution_id": res.execution_id,
        "scanned_bytes": res.scanned_bytes,
        "estimated_bytes": estimated_bytes,
        "running_total": engine.gauge.summary(),
    }
