# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: bytes a query would scan, from S3 object sizes under the partitions it touches."""

from __future__ import annotations

from ..core import s3layout
from ..core.athena import CostGauge


def estimate_scan(
    log_inventory: s3layout.LogInventory,
    first_day: str,
    last_day: str,
    gauge: CostGauge,
    accounts: set[str] | None = None,
    regions: set[str] | None = None,
) -> dict:
    nbytes = s3layout.estimate_bytes(log_inventory, first_day, last_day, accounts, regions)
    est = gauge.estimate(nbytes)
    est["decision"] = gauge.decide(est)
    est["window"] = [first_day, last_day]
    est["running_total_cost_usd"] = gauge.total_cost_usd
    return est
