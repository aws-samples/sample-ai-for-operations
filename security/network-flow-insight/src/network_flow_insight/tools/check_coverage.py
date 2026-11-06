# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: integrity findings.

Compares what the table can see with what is in S3, shares of SKIPDATA/NODATA records, and gateways
that have no flow log in the table. Pure functions over structured inputs.
"""

from __future__ import annotations

from ..core.tablescheme import window_days
from ._common import n, share


def _visibility_fn(visibility: dict):
    if visibility.get("mode") == "enumerated":
        listed = {tuple(p) for p in visibility.get("partitions", [])}
        return lambda acct, region, day: (acct, region, day) in listed

    def projected(acct: str, region: str, day: str) -> bool:
        if visibility.get("accounts") is not None and acct not in visibility["accounts"]:
            return False
        if visibility.get("regions") is not None and region not in visibility["regions"]:
            return False
        first = visibility.get("first_day")
        return not (first and day < first)

    return projected


def log_status_shares(rows: list[dict], threshold: float) -> dict:
    total = sum(n(r.get("records")) for r in rows)
    skip = sum(n(r.get("records")) for r in rows if r.get("log_status") == "SKIPDATA")
    nodata = sum(n(r.get("records")) for r in rows if r.get("log_status") == "NODATA")
    skip_pct = share(skip, total)
    return {
        "total_records": total,
        "skipdata_records": skip,
        "nodata_records": nodata,
        "skipdata_share_pct": skip_pct,
        "nodata_share_pct": share(nodata, total),
        "threshold_pct": round(threshold * 100, 2),
        "caution": bool(total and skip / total > threshold),
    }


def check_coverage(
    s3_partitions: list[dict],
    visibility: dict,
    first_day: str,
    last_day: str,
    *,
    aggregate_rows: list[dict] | None = None,
    skipdata_threshold: float = 0.02,
    gateway_interfaces: list[dict] | None = None,
) -> dict:
    """Integrity findings for the window.

    ``s3_partitions``: ``[{account_id, region, day, bytes}]`` present in S3 (from ``list_log_prefixes``).
    ``visibility``: how the table sees partitions: ``{"mode": "projection", "accounts": [...],
    "regions": [...], "first_day": "..."}`` or ``{"mode": "enumerated", "partitions": [[a, r, d], ...]}``.
    ``gateway_interfaces``: ``[{interface_id, kind, gateway_id, account_id}]`` from the inventory.
    """
    days = set(window_days(first_day, last_day))
    visible = _visibility_fn(visibility)
    in_window = [p for p in s3_partitions if p["day"] in days]
    missing = [p for p in in_window if not visible(p["account_id"], p["region"], p["day"])]
    out: dict = {
        "window": [first_day, last_day],
        "s3_partitions": len(in_window),
        "visible_partitions": len(in_window) - len(missing),
        "missing_partitions": [
            {
                "account_id": p["account_id"],
                "region": p["region"],
                "day": p["day"],
                "bytes": p.get("bytes", 0),
            }
            for p in sorted(missing, key=lambda p: (p["account_id"], p["region"], p["day"]))
        ],
        "missing_accounts": sorted({p["account_id"] for p in missing}),
        "missing_regions": sorted({p["region"] for p in missing}),
        "missing_days": sorted({p["day"] for p in missing}),
        "missing_bytes": sum(n(p.get("bytes")) for p in missing),
        "days_without_any_data": sorted(days - {p["day"] for p in in_window}),
    }
    out["caution"] = bool(missing)
    out["excluded_from_totals"] = bool(missing)
    if aggregate_rows is not None:
        out["log_status"] = log_status_shares(aggregate_rows, skipdata_threshold)
        out["caution"] = out["caution"] or out["log_status"]["caution"]
        seen_ifaces = {r.get("interface_id") for r in aggregate_rows}
        if gateway_interfaces is not None:
            unlogged = [g for g in gateway_interfaces if g["interface_id"] not in seen_ifaces]
            out["gateway_interfaces_without_records"] = sorted(unlogged, key=lambda g: g["interface_id"])
            out["gateway_interfaces_note"] = (
                "No records in the window: the interface was idle, or has no flow log attached. This tool cannot tell which."
            )
            logged_accounts = {
                p["account_id"] for p in in_window if visible(p["account_id"], p["region"], p["day"])
            }
            out["accounts_with_gateways_but_no_flow_log"] = sorted(
                {
                    g["account_id"]
                    for g in gateway_interfaces
                    if g.get("account_id") and g["account_id"] not in logged_accounts
                }
            )
            if unlogged:
                out["caution"] = True
    return out
