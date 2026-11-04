# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: read the flow-log table's schema, partitioning, visibility and log-status mix."""

from __future__ import annotations

import re
from typing import Any

from ..core import s3layout
from ..core.athena import GaugedEngine, QuerySkipped
from ..core.tablescheme import TableScheme, detect_scheme, refine_day_kind, sql_literal, window_days

_ISO_FROM_FORMAT = {"yyyy/MM/dd": "%Y/%m/%d", "yyyy-MM-dd": "%Y-%m-%d"}


def find_flow_log_tables(glue: Any, database: str | None = None) -> list[dict]:
    """Candidate flow-log tables in the Glue catalog: tables that carry srcaddr, dstaddr and interface_id."""
    dbs = (
        [database]
        if database
        else [d["Name"] for p in glue.get_paginator("get_databases").paginate() for d in p["DatabaseList"]]
    )
    found = []
    for db in dbs:
        for page in glue.get_paginator("get_tables").paginate(DatabaseName=db):
            for t in page["TableList"]:
                cols = {
                    c["Name"].lower().replace("-", "_")
                    for c in t.get("StorageDescriptor", {}).get("Columns", [])
                }
                if {"srcaddr", "dstaddr", "interface_id"} <= cols:
                    found.append(
                        {
                            "database": db,
                            "table": t["Name"],
                            "location": t.get("StorageDescriptor", {}).get("Location", ""),
                        }
                    )
    return found


def probe_table(
    glue: Any,
    database: str,
    table: str,
    first_day: str,
    last_day: str,
    *,
    engine: GaugedEngine | None = None,
    log_inventory: s3layout.LogInventory | None = None,
) -> dict:
    t = glue.get_table(DatabaseName=database, Name=table)["Table"]
    sd = t.get("StorageDescriptor", {})
    columns = [c["Name"] for c in sd.get("Columns", [])]
    keys = [k["Name"] for k in t.get("PartitionKeys", [])]
    serde = sd.get("SerdeInfo", {}).get("SerializationLibrary", "").lower()
    fmt = "parquet" if "parquet" in serde else "text"
    params = t.get("Parameters", {})
    projection = str(params.get("projection.enabled", "false")).lower() == "true"
    scheme = detect_scheme(database, table, columns, keys, fmt)
    visibility: dict
    if projection:
        visibility = _projection_visibility(params, scheme)
        scheme = _refine_from_projection(scheme, params)
    else:
        parts = _enumerate_partitions(glue, database, table, scheme, keys)
        visibility = {"mode": "enumerated", "partitions": parts[0]}
        if parts[1]:
            scheme = refine_day_kind(scheme, parts[1])
    present = (
        sorted({d for (_, _, d) in map(tuple, visibility.get("partitions", []))})
        if visibility["mode"] == "enumerated"
        else None
    )
    out: dict = {
        "database": database,
        "table": table,
        "fields": list(scheme.fields),
        "file_format": fmt,
        "partition_keys": keys,
        "projection": projection,
        "scheme": _scheme_dict(scheme),
        "visibility": {k: v for k, v in visibility.items() if k != "partitions"}
        | ({"partition_count": len(visibility["partitions"])} if visibility["mode"] == "enumerated" else {}),
        "visibility_full": visibility,
        "days_with_partitions": present,
        "recommendations": []
        if projection
        else [
            "The table uses enumerated partitions. Partition projection removes the need to keep partitions current "
            "and prevents silent gaps; the agent does not change existing tables."
        ],
        "skipdata_sample": None,
    }
    if engine is not None and log_inventory is not None:
        out["skipdata_sample"] = _skipdata_sample(engine, scheme, log_inventory, last_day)
    return out


def _scheme_dict(s: TableScheme) -> dict:
    return {k: (list(v) if isinstance(v, tuple) else v) for k, v in s.__dict__.items()}


def scheme_from_dict(d: dict) -> TableScheme:
    d = dict(d)
    d["fields"] = tuple(d["fields"])
    d["extra_partitions"] = tuple(d.get("extra_partitions", ()))
    return TableScheme(**d)


def _projection_visibility(params: dict, scheme: TableScheme) -> dict:
    def enum(col: str | None) -> list[str] | None:
        if not col:
            return None
        if str(params.get(f"projection.{col}.type", "")).lower() != "enum":
            return None
        return [v.strip() for v in str(params.get(f"projection.{col}.values", "")).split(",") if v.strip()]

    first = None
    rng = str(params.get(f"projection.{scheme.day_col}.range", ""))
    fmt = str(params.get(f"projection.{scheme.day_col}.format", ""))
    if rng and fmt in _ISO_FROM_FORMAT:
        from datetime import datetime

        start = rng.split(",")[0].strip()
        try:
            first = datetime.strptime(start, _ISO_FROM_FORMAT[fmt]).date().isoformat()
        except ValueError:
            first = None
    return {
        "mode": "projection",
        "accounts": enum(scheme.account_col),
        "regions": enum(scheme.region_col),
        "first_day": first,
    }


def _refine_from_projection(scheme: TableScheme, params: dict) -> TableScheme:
    fmt = str(params.get(f"projection.{scheme.day_col}.format", ""))
    if scheme.day_kind == "ymd" or not fmt:
        return scheme
    return refine_day_kind(scheme, "2000/01/01" if "/" in fmt else "2000-01-01")


def _enumerate_partitions(
    glue: Any, database: str, table: str, scheme: TableScheme, keys: list[str]
) -> tuple[list[list[str]], str]:
    norm = [k.lower().replace("-", "_") for k in keys]
    triples: list[list[str]] = []
    sample = ""
    for page in glue.get_paginator("get_partitions").paginate(DatabaseName=database, TableName=table):
        for p in page["Partitions"]:
            vals = dict(zip(norm, p["Values"], strict=False))
            if scheme.day_kind == "ymd":
                try:
                    day = f"{int(vals[scheme.year_col]):04d}-{int(vals[scheme.month_col]):02d}-{int(vals[scheme.day_col]):02d}"
                except (KeyError, ValueError):
                    continue
            else:
                raw = vals.get(scheme.day_col, "")
                sample = sample or raw
                day = raw.replace("/", "-")
                if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                    continue
            acct = vals.get(scheme.account_col or "", "*")
            reg = vals.get(scheme.region_col or "", "*")
            triples.append([acct, reg, day])
    return triples, sample


def _skipdata_sample(
    engine: GaugedEngine, scheme: TableScheme, inv: s3layout.LogInventory, last_day: str
) -> dict:
    sql = (
        f"SELECT log_status, COUNT(*) AS records FROM {scheme.qualified} "  # nosec B608 - identifiers pass ident(); values are quoted or parsed
        f"WHERE {scheme.window_predicate(last_day, last_day)} GROUP BY 1"
    )
    est = s3layout.estimate_bytes(inv, last_day, last_day)
    try:
        res = engine.run(sql, estimated_bytes=est, label="probe: log-status sample", max_rows=10)
    except QuerySkipped as exc:
        return {"skipped": str(exc)}
    total = sum(int(r["records"]) for r in res.rows)
    skip = sum(int(r["records"]) for r in res.rows if r["log_status"] == "SKIPDATA")
    return {
        "day": last_day,
        "records": total,
        "skipdata_records": skip,
        "skipdata_share_pct": round(skip / total * 100, 2) if total else None,
        "execution_id": res.execution_id,
        "scanned_bytes": res.scanned_bytes,
    }


__all__ = ["find_flow_log_tables", "probe_table", "scheme_from_dict", "sql_literal", "window_days"]
