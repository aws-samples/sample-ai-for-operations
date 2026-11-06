# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: billed usage by usage type from the Cost and Usage Report via Athena (optional)."""

from __future__ import annotations

from ..core.athena import GaugedEngine, QuerySkipped
from ..core.sqlsafe import SqlPolicy, SqlRejected, validate
from ..core.tablescheme import ident, iso_day, sql_literal

USAGE_SUFFIXES = ("NatGateway-Bytes", "DataTransfer-Out-Bytes", "DataTransfer-Regional-Bytes")


def query_cur(
    engine: GaugedEngine,
    database: str,
    table: str,
    first_day: str,
    last_day: str,
    accounts: list[str],
    *,
    estimated_bytes: int = 50_000_000,
) -> list[dict] | str:
    """Rows ``{account_id, usage_type, usage_gb}`` for the window and account set, or a reason string."""
    ident(database), ident(table)
    first_day, last_day = iso_day(first_day), iso_day(last_day)
    like = " OR ".join(f"line_item_usage_type LIKE '%{s}'" for s in USAGE_SUFFIXES)
    accts = ", ".join(sql_literal(a) for a in accounts)
    sql = (
        f"SELECT line_item_usage_account_id AS account_id, line_item_usage_type AS usage_type, "  # nosec B608 - identifiers pass ident(); values are quoted or parsed
        f"SUM(line_item_usage_amount) AS usage_gb FROM {database}.{table} "
        f"WHERE line_item_usage_start_date >= TIMESTAMP '{first_day} 00:00:00' "
        f"AND line_item_usage_start_date < date_add('day', 1, TIMESTAMP '{last_day} 00:00:00') "
        f"AND line_item_usage_account_id IN ({accts}) AND ({like}) GROUP BY 1, 2"
    )
    try:
        safe = validate(sql, SqlPolicy({table: ()}, max_limit=5000))
        res = engine.run(safe, estimated_bytes=estimated_bytes, label="CUR", max_rows=5000)
    except (SqlRejected, QuerySkipped) as exc:
        return f"CUR query not run: {exc}"
    except Exception as exc:
        return f"CUR query failed: {type(exc).__name__}: {str(exc)[:160]}"
    return [
        {
            "account_id": str(r["account_id"]),
            "usage_type": r["usage_type"],
            "usage_gb": float(r["usage_gb"] or 0),
        }
        for r in res.rows
    ]
