# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: the one raw scan per window. CTAS the aggregate into Parquet and register it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ..core import s3layout
from ..core.aggregate import aggregate_select, aggregate_table_name, source_tag
from ..core.athena import GaugedEngine
from ..core.sqlsafe import SqlPolicy, validate
from ..core.tablescheme import TableScheme


def settle_point(last_day: str, settle_minutes: int) -> datetime:
    """When every flow record for ``last_day`` can be assumed delivered: the end of the day plus a margin."""
    return datetime.fromisoformat(last_day).replace(tzinfo=UTC) + timedelta(days=1, minutes=settle_minutes)


def window_settled(last_day: str, settle_minutes: int, now: datetime | None = None) -> bool:
    return (now or datetime.now(UTC)) >= settle_point(last_day, settle_minutes)


def find_aggregate(
    glue: Any,
    database: str,
    first_day: str,
    last_day: str,
    *,
    settle_minutes: int = 60,
    table: str | None = None,
    source: str = "",
) -> dict | None:
    """Return the registered aggregate for the window if it exists (chat mode reuses it).

    An aggregate built before the window settled (see ``settle_point``) may miss late-delivered records; it is
    returned with ``stale: True`` and must not be reused. ``table`` looks up a specific (versioned) build, for
    example to read where a workgroup that enforces its output location actually wrote it.
    """
    if not table and not source:
        raise ValueError("find_aggregate needs the aggregate table name or the source flow-log table")
    name = table or aggregate_table_name(first_day, last_day, source)
    try:
        t = glue.get_table(DatabaseName=database, Name=name)["Table"]
    except Exception as exc:  # EntityNotFoundException and friends: treat as absent
        if getattr(exc, "response", {}).get("Error", {}).get("Code") not in ("EntityNotFoundException", None):
            raise
        return None
    found = {"aggregate_table": name, "location": t["StorageDescriptor"]["Location"], "reused": True}
    created = t.get("CreateTime")
    if isinstance(created, datetime):
        created = created if created.tzinfo else created.replace(tzinfo=UTC)
        if created < settle_point(last_day, settle_minutes):
            found.update(reused=False, stale=True, created=created.isoformat())
    return found


def build_aggregate(
    scheme: TableScheme,
    first_day: str,
    last_day: str,
    engine: GaugedEngine,
    log_inventory: s3layout.LogInventory,
    *,
    agg_database: str,
    results_prefix: str,
    dialect: str = "trino",
    accounts: set[str] | None = None,
    regions: set[str] | None = None,
    version: str = "",
) -> dict:
    """``version`` (for example a build timestamp) gives the aggregate its own table name and location. It is
    used for a window that has not settled yet, or one whose registered aggregate is stale: CTAS cannot
    overwrite a table or write into a non-empty location, and those builds must never be reused.
    """
    select = aggregate_select(scheme, first_day, last_day, dialect)
    validate(
        select + "\nLIMIT 1000000", SqlPolicy({scheme.table: scheme.partition_cols}, max_limit=1_000_000)
    )
    if version and not version.isalnum():
        raise ValueError("aggregate version must be alphanumeric")
    table = aggregate_table_name(first_day, last_day, scheme.qualified) + (f"_b{version}" if version else "")
    base = results_prefix.rstrip("/")
    location = (
        f"{base}/nfi/aggregate/source={source_tag(scheme.qualified)}/window={first_day}_{last_day}/"
        + (f"build={version}/" if version else "")
    )
    est = s3layout.estimate_bytes(log_inventory, first_day, last_day, accounts, regions)
    res = engine.ctas(
        f"{agg_database}.{table}", select, location, estimated_bytes=est, label="build aggregate"
    )
    return {
        "aggregate_table": table,
        "database": agg_database,
        "location": location,
        "execution_id": res.execution_id,
        "scanned_bytes": res.scanned_bytes,
        "estimated_bytes": est,
        "reused": False,
        "version": version or None,
        "sql": select,
        "window": [first_day, last_day],
    }
