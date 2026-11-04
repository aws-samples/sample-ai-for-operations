# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The model-facing tool surface.

The pure tools in ``network_flow_insight.tools`` take data. A model should not pass data around, so
``ToolSession`` holds the session state (window, aggregate rows, inventory, classification, findings) and
exposes the same tools with short arguments: days, dimension names, SQL. Strands, the MCP server and the
CLI all use these methods, so the three surfaces return the same figures.

Every method returns JSON-safe data. Long lists are capped with an explicit ``rows_total`` so a model is
never silently handed a partial table.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import date
from typing import Any

from .analysis import Analysis
from .core import s3layout
from .core.athena import QuerySkipped
from .core.intent_schema import dump_intent
from .core.units import to_units as _to_units
from .tools import (
    aggregate_by,
    assign_tier,
    check_coverage,
    classify_destination,
    estimate_scan,
    query_raw,
    render_report,
    top_n,
    write_report,
)
from .tools.get_inventory import PROVIDER_OPTIONS
from .tools.query_aggregate import query_aggregate as _qa

MAX_ROWS = 60
DIMENSIONS = (
    "day",
    "hour",
    "account_id",
    "region",
    "interface_id",
    "vpc_id",
    "subnet_id",
    "az_id",
    "path_class",
    "method",
    "direction",
    "local_addr",
    "remote_addr",
    "remote_port",
    "protocol",
    "action",
    "dest_bucket",
    "dest_service",
)


_BYTE_KEYS = frozenset({"bytes", "c2s", "s2c", "out", "back", "current", "previous", "delta"})


def _is_byte_key(k: Any) -> bool:
    return isinstance(k, str) and (k in _BYTE_KEYS or k.endswith("_bytes"))


def cap(obj: Any, max_rows: int = MAX_ROWS) -> Any:
    """Cap long lists (recursively) and say so. Byte counts also get a labelled decimal-unit text field,
    so a model quotes the tool's formatting instead of converting units itself."""
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for k, v in obj.items():
            out[k] = cap(v, max_rows)
            if _is_byte_key(k) and isinstance(v, int) and not isinstance(v, bool):
                out[f"{k}_text"] = _to_units(v)["text"]
        return out
    if isinstance(obj, list):
        if len(obj) > max_rows and obj and isinstance(obj[0], dict):
            return [cap(v, max_rows) for v in obj[:max_rows]] + [
                {"truncated": True, "rows_total": len(obj), "rows_shown": max_rows}
            ]
        return [cap(v, max_rows) for v in obj]
    if isinstance(obj, set | tuple):
        return cap(sorted(obj, key=str), max_rows)
    return obj


class ToolSession:
    def __init__(self, analysis: Analysis, *, today: date | None = None) -> None:
        self.a = analysis
        self.today = today
        self.findings: dict[str, Any] | None = None
        self.findings_window: tuple[str, str] | None = None
        self.narrative: dict[str, str] = {}

    # ---- helpers ---------------------------------------------------------------------------
    def _window(self, first_day: str = "", last_day: str = "") -> tuple[str, str]:
        if first_day and last_day:
            date.fromisoformat(first_day)
            date.fromisoformat(last_day)
            return first_day, last_day
        if self.findings_window:
            return self.findings_window
        return s3layout.previous_complete_days(self.today or date.today(), self.a.s.default_window_days)

    def _classified(self, first_day: str = "", last_day: str = ""):
        a, b = self._window(first_day, last_day)
        return self.a.ready(a, b)

    # ---- tools -----------------------------------------------------------------------------
    def probe(self, first_day: str = "", last_day: str = "") -> dict:
        """Probe before analysing: table fields, partitioning, capability tier, inventory provider, S3 coverage.

        Runs no analysis query. Returns the tier, what it allows, what would raise it, and the integrity
        findings that need no scan. Call this first and state the tier and provider before anything else.
        """
        a, b = self._window(first_day, last_day)
        tier = assign_tier.assign_tier(
            list(self.a.b.scheme.fields), self.a.b.inventory_provider if self.a.b.inventory else "D"
        )
        cov = check_coverage.check_coverage(
            self.a.b.log_inventory.summary()["partitions"],
            self.a.b.visibility,
            a,
            b,
            skipdata_threshold=self.a.s.skipdata_threshold,
        )
        return cap(
            {
                "window": [a, b],
                "raw_table": self.a.b.scheme.qualified,
                "fields": list(self.a.b.scheme.fields),
                "partitioning": self.a.b.visibility.get("mode"),
                "tier": tier,
                "inventory": self._inventory_summary(),
                "coverage": cov,
                "scan_estimate": self.estimate_scan(a, b),
            }
        )

    def _inventory_summary(self) -> dict:
        """Provider and note; when there is no inventory, also the ways to get one."""
        out = {
            "provider": self.a.b.inventory_provider if self.a.b.inventory else "D",
            "note": self.a.b.provider_note,
        }
        if not self.a.b.inventory:
            out["options"] = PROVIDER_OPTIONS
        return out

    def estimate_scan(self, first_day: str = "", last_day: str = "") -> dict:
        """Estimated bytes and cost of the one raw scan for the window, from S3 object sizes. Scans nothing."""
        a, b = self._window(first_day, last_day)
        return estimate_scan.estimate_scan(self.a.b.log_inventory, a, b, self.a.b.engine.gauge)

    def describe(self, first_day: str = "", last_day: str = "", compare_previous: bool = True) -> dict:
        """Run the full describe-mode workflow for the window (default: last 7 complete days).

        Builds the aggregate once (one raw scan), classifies paths and destinations, scopes NAT, reconciles
        and computes every report section. Returns the headlines, cautions, reconciliation verdict and the
        names of the sections to fetch with ``get_section``. All figures come from precision tools.
        """
        a, b = self._window(first_day, last_day)
        try:
            self.findings = self.a.describe(a, b, compare_previous=compare_previous)
        except QuerySkipped as exc:
            return {"status": "skipped", "reason": str(exc), "executed": False}
        self.findings_window = (a, b)
        f = self.findings
        return cap(
            {
                "status": "ok",
                "window": [a, b],
                "tier": f["tier"]["tier"],
                "inventory_provider": f["meta"]["inventory_provider"],
                "reconciliation": {
                    k: f["reconciliation"][k]
                    for k in ("verdict", "show_shares", "shares_caution", "rungs_used", "rungs_unavailable")
                },
                "headlines": f["headlines"],
                "cautions": f["cautions"],
                "scan": f["meta"]["scan"],
                "sections": sorted(
                    k for k in f if k not in ("meta", "queries", "blind_spots", "headlines", "cautions")
                ),
            }
        )

    def get_section(self, name: str) -> dict:
        """Fetch one computed section of the findings (for example ``path_volume``, ``nat``, ``reconciliation``)."""
        if self.findings is None:
            return {"error": "run describe first"}
        if name not in self.findings:
            return {"error": f"unknown section {name!r}", "sections": sorted(self.findings)}
        return cap({name: self.findings[name]})

    def aggregate(
        self,
        dims: list[str],
        measures: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        limit: int = 20,
        first_day: str = "",
        last_day: str = "",
    ) -> dict:
        """Sum bytes, packets or records by dimensions over the classified, counted aggregate rows.

        ``dims`` from: day, hour, account_id, region, interface_id, vpc_id, subnet_id, az_id, path_class,
        method, direction, local_addr, remote_addr, remote_port, protocol, action, dest_bucket,
        dest_service. ``filters`` maps a dimension to a value or list of values. Exact, from code.
        """
        bad = [d for d in dims if d not in DIMENSIONS]
        if bad:
            return {"error": f"unknown dimensions {bad}", "allowed": list(DIMENSIONS)}
        wd = self._classified(first_day, last_day)
        for r in wd.classified:
            d = self.a.dest_map.get(r.get("remote_addr") or "", {})
            r.setdefault("dest_bucket", d.get("bucket"))
            r.setdefault("dest_service", d.get("service"))
        res = aggregate_by.aggregate_by(wd.classified, dims, measures, filters=filters)
        ranked = top_n.top_n(res["rows"], limit, (measures or ["bytes"])[0])
        return cap(
            {
                "dims": dims,
                "total": res["total"],
                "groups": res["groups"],
                "top": ranked["rows"],
                "others": ranked["others"],
                "window": [wd.first_day, wd.last_day],
            }
        )

    def classify_addresses(self, ips: list[str]) -> dict:
        """Classify remote addresses: own VPC, named network, AWS service, AWS-hosted unverified, other internet."""
        inv = None if self.a.inferred else self.a.inventory
        return cap(
            classify_destination.classify_destination(
                ips[:500],
                inv,
                self.a.b.intent,
                self.a.b.ranges,
                home_region=self.a.b.home_region,
                resolver_names=self.a.resolver_names,
            )
        )

    def query_aggregate(self, sql: str) -> dict:
        """Run a SELECT against the aggregate table(s) only. Must bound ``day``; LIMIT is capped. Cheap."""
        tables = [wd.table for wd in self.a.windows.values()]
        if not tables:
            return {
                "status": "rejected",
                "reason": "no aggregate built yet; run describe first",
                "executed": False,
            }
        out = _qa(
            sql,
            tables,
            self.a.b.engine,
            aggregate_bytes=20_000_000,
            max_limit=self.a.s.max_chat_limit,
            database=self.a.b.agg_database,
        )
        return cap(out)

    def query_raw(self, sql: str, first_day: str = "", last_day: str = "") -> dict:
        """Run a SELECT against the raw flow-log table. Gauged against the whole window; use only if the
        aggregate cannot answer. The WHERE clause must give a literal start and end date on the day column, both
        inside the window (a rejection shows the exact form). May be skipped above the cost ceiling."""
        a, b = self._window(first_day, last_day)
        out = query_raw.query_raw(
            sql,
            self.a.b.scheme,
            self.a.b.engine,
            self.a.b.log_inventory,
            a,
            b,
            max_limit=self.a.s.max_chat_limit,
        )
        return cap(out)

    def metric_trend(self, gateway_id: str, first_day: str, last_day: str) -> dict:
        """Bytes through a NAT gateway from CloudWatch metrics for the window. Reads no flow logs (no scan)."""
        if self.a.b.metrics_fn is None:
            return {"status": "unavailable", "why": "no metrics source configured", "scanned_bytes": 0}
        res = self.a.b.metrics_fn([{"kind": "nat", "id": gateway_id}], first_day, last_day)
        if isinstance(res, str):
            return {"status": "unavailable", "why": res, "scanned_bytes": 0}
        return {"status": "ok", "metrics": res, "scanned_bytes": 0, "source": "CloudWatch"}

    def intent_draft(self, first_day: str = "", last_day: str = "") -> dict:
        """Draft a baseline intent file from the observed window, with evidence per entry, for a human to prune."""
        a, b = self._window(first_day, last_day)
        doc = self.a.intent_draft(a, b)
        from .core.intent_schema import Intent

        return {
            "entries": len(doc["baseline"]),
            "yaml": dump_intent(Intent.model_validate(doc)),
            "window": [a, b],
        }

    def drift(self, first_day: str = "", last_day: str = "") -> dict:
        """Compare the window with the committed baseline: matched, new, stale, path-changed. Never edits it."""
        a, b = self._window(first_day, last_day)
        return cap(self.a.intent_drift(a, b))

    def what_if(self, first_day: str = "", last_day: str = "") -> dict:
        """Treat the committed baseline as enforced egress policy: share of bytes and conversations denied."""
        a, b = self._window(first_day, last_day)
        return cap(self.a.intent_what_if(a, b))

    def render_report(self, narrative: dict[str, str] | None = None) -> dict:
        """Render the layered report and data pack from the findings and write them. ``narrative`` maps
        section keys (summary, integrity, paths, egress, services, inter_vpc, nat, concentration, time,
        options) to short interpretation text. Numbers in the narrative must appear in the findings. The report is written
        to the configured reports directory; the destination cannot be chosen by the caller."""
        if self.findings is None:
            return {"error": "run describe first"}
        self.narrative = dict(narrative or {})
        art = render_report.render_report(self.findings, narrative)
        dest = self.a.s.reports_dir
        stamp = f"{self.findings_window[0]}_{self.findings_window[1]}" if self.findings_window else "report"
        res = write_report.write_report(art, local_dir=f"{dest}/{stamp}")
        return {"written": res["written"], "destination": res["destination"]}

    def to_units(self, num_bytes: int) -> dict:
        """Convert bytes to labelled decimal units."""
        return _to_units(num_bytes)


def tool_methods(session: ToolSession) -> list[Callable[..., Any]]:
    """The bound methods exposed to models and MCP hosts, in the order the method uses them."""
    names = (
        "probe",
        "estimate_scan",
        "describe",
        "get_section",
        "aggregate",
        "classify_addresses",
        "query_aggregate",
        "query_raw",
        "metric_trend",
        "intent_draft",
        "drift",
        "what_if",
        "render_report",
        "to_units",
    )
    return [getattr(session, n) for n in names]


def jsonable(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, default=str)
