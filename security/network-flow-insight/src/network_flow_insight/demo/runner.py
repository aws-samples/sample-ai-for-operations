# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Assemble an ``Analysis`` over the synthetic estate (no AWS credentials, DuckDB instead of Athena)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..analysis import Analysis, Backend
from ..config import Settings
from ..core import s3layout
from ..core.athena import CostGauge, GaugedEngine
from ..core.intent_schema import load_intent
from ..core.inventory import Inventory
from ..core.ipranges import IpRanges, load_document
from . import estate as E
from .duck import DuckDBEngine
from .generator import Estate, generate
from .localfs import LocalS3

BUCKET = "example-flow-logs"


def _read(p: Path) -> Any:
    return json.loads(p.read_text())


def build_backend(
    est: Estate,
    settings: Settings,
    *,
    inventory: bool = True,
    table_accounts: list[str] | None = None,
    with_metrics: bool = True,
    with_cur: bool = True,
    with_resolver: bool = True,
    reference: dict | None = None,
    cur_accounts: list[str] | None = None,
    interactive: bool = False,
) -> Backend:
    duck = DuckDBEngine(est.s3_root, "nfi", "flow_logs", accounts=table_accounts)
    prices = _read(est.prices_path)
    gauge = CostGauge(prices["athena_per_tb"], settings.scan_ceiling_usd, settings.session_budget_usd)
    engine = GaugedEngine(duck, gauge, interactive=interactive)
    first, last = E.WINDOW_A[0], E.WINDOW_B[1]
    log_inv = s3layout.walk(LocalS3(est.s3_root), BUCKET, first, last)
    accounts = table_accounts if table_accounts is not None else sorted(log_inv.accounts)
    visibility = {
        "mode": "projection",
        "accounts": accounts,
        "regions": sorted(log_inv.regions),
        "first_day": first,
    }
    inv = Inventory(_read(est.inventory_path)) if inventory else None
    metrics = _read(est.metrics_path)
    cur = _read(est.cur_path)
    names = _read(est.resolver_path)

    def metrics_fn(gws: list[dict], a: str, b: str) -> Any:
        w = metrics_window(metrics, a, b)
        out = {g["id"]: w[g["id"]] for g in gws if g["id"] in w}
        return out or "no gateway metrics in the fixture for this window"

    def cur_fn(a: str, b: str, accts: list[str]) -> Any:
        rows = cur.get(f"{a}..{b}")
        if rows is None:
            return "no CUR extract for this window"
        keep = cur_accounts if cur_accounts is not None else accts
        return [r for r in rows if r["account_id"] in keep]

    def resolver_fn(ips: list[str], a: str, b: str) -> Any:
        return {ip: names[ip] for ip in ips if ip in names}

    return Backend(
        engine=engine,
        scheme=duck.scheme,
        log_inventory=log_inv,
        visibility=visibility,
        dialect="duckdb",
        agg_database="nfi",
        results_prefix="s3://example-results/",
        inventory_provider="C" if inv else "D",
        inventory=inv,
        provider_note="synthetic inventory file" if inv else "no inventory provider",
        ranges=IpRanges(load_document(est.ip_ranges_path)),
        rates=prices,
        intent=load_intent(est.intent_path),
        home_region=E.REGION,
        metrics_fn=metrics_fn if with_metrics else None,
        cur_fn=cur_fn if with_cur else None,
        resolver_fn=resolver_fn if with_resolver else None,
        reference=reference,
        mode="demo",
        tables={"raw": "nfi.flow_logs (DuckDB, synthetic)", "workgroup": "local-duckdb"},
    )


def metrics_window(metrics: dict, a: str, b: str) -> dict:
    return {gw: v[f"{a}..{b}"] for gw, v in metrics.items() if f"{a}..{b}" in v}


def build_analysis(
    out_dir: str | Path, tier: str = "full", settings: Settings | None = None, **kw: Any
) -> tuple[Analysis, Estate]:
    est = generate(out_dir, tier)
    s = settings or Settings(aws_region=E.REGION)
    return Analysis(s, build_backend(est, s, **kw)), est
