# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The describe-mode workflow, expressed as calls to the tool layer.

``Analysis`` holds the state of one session (window, aggregate, inventory, classification) and exposes
one method per workflow step. The Strands agent, the MCP server and ``nfi demo`` all drive these same
steps; the agent decides the order and the prose, the steps produce every number. ``describe()`` runs the
whole sequence deterministically and returns the findings that ``render_report`` turns into the report.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .config import Settings
from .core import s3layout
from .core.aggregate import aggregate_table_name
from .core.athena import GaugedEngine, QuerySkipped
from .core.intent_schema import Intent
from .core.inventory import Inventory
from .core.ipranges import IpRanges, is_private
from .core.tablescheme import TableScheme, ident, iso_day, window_days
from .tools import (
    aggregate_by,
    assign_tier,
    build_aggregate,
    check_coverage,
    classify_destination,
    classify_path,
    detect_forwarding_interfaces,
    draft_intent,
    drift,
    endpoint_effectiveness,
    enrich_conversations,
    gateway_utilisation,
    nat_leg_check,
    nat_scope,
    pair_conversations,
    period_compare,
    price_context,
    reconcile,
    time_profile,
    top_n,
    what_if,
)
from .tools._common import counted_rows, share

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)

BLIND_SPOTS = (
    "VPC Flow Logs do not capture traffic to the Amazon DNS resolver, instance metadata, Amazon Time Sync, "
    "DHCP, Windows licence activation, or the VPC router reserved address.",
    "Some traffic between endpoint interfaces and Network Load Balancer interfaces is not captured, and logs "
    "vended directly by AWS services to their destinations are not flow-log records.",
    "Records are aggregated over the capture window (1 or 10 minutes) and are not real-time.",
    "SKIPDATA records mean the capture dropped data; NODATA records mean no traffic in the window.",
    "Interfaces without a flow log attached, and partitions the table cannot see, are invisible.",
    "Interfaces deleted since the window cannot be attributed below Enhanced tier.",
    "Gateway endpoints have no interface, so their traffic is inferred from route tables.",
    "Byte counts include IP headers and differ from payload-based billing by protocol framing.",
    "This report is evidence for a governance conversation. It is not an attestation and does not claim completeness.",
)

INTERNET_PATHS = ("internet-nat", "internet-igw", "internet-unresolved")


@dataclass
class Backend:
    """Everything environment-specific. The workflow itself never touches boto3 or DuckDB directly."""

    engine: GaugedEngine
    scheme: TableScheme
    log_inventory: s3layout.LogInventory
    visibility: dict
    dialect: str
    agg_database: str
    results_prefix: str
    inventory_provider: str
    inventory: Inventory | None
    provider_note: str
    ranges: IpRanges
    rates: dict
    intent: Intent | None = None
    home_region: str = ""
    metrics_fn: Callable[[list[dict], str, str], Any] | None = None
    cur_fn: Callable[[str, str, list[str]], Any] | None = None
    resolver_fn: Callable[[list[str], str, str], Any] | None = None
    find_aggregate_fn: Callable[..., dict | None] | None = None  # (first, last, table=None)
    extend_log_fn: Callable[[str, str], None] | None = None
    reference: dict | None = None
    read_parquet_fn: Callable[[str], list[dict]] | None = None
    mode: str = "aws"
    tables: dict = field(default_factory=dict)


@dataclass
class WindowData:
    first_day: str
    last_day: str
    table: str
    build: dict
    rows: list[dict]
    classified: list[dict] = field(default_factory=list)
    conversations: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


def _require(value):
    if value is None:
        raise RuntimeError("required value missing: run the earlier workflow step first")
    return value


class Analysis:
    def __init__(self, settings: Settings, backend: Backend) -> None:
        self.s = settings
        self.b = backend
        self.windows: dict[tuple[str, str], WindowData] = {}
        self.inferred = backend.inventory is None
        self.detection: dict | None = None
        self.inventory: Inventory | None = backend.inventory
        self.dest_map: dict[str, dict] = {}
        self.resolver_names: dict[str, list[str]] = {}
        self.resolver_status: str = "not configured"

    # ---- step: aggregate --------------------------------------------------------------------
    def window_data(self, first_day: str, last_day: str, *, required: bool = True) -> WindowData | None:
        key = (first_day, last_day)
        if key in self.windows:
            return self.windows[key]
        if self.b.extend_log_fn is not None:
            self.b.extend_log_fn(first_day, last_day)  # so the cost gauge sees this window's bytes
        table = aggregate_table_name(first_day, last_day, self.b.scheme.qualified)
        existing = self.b.find_aggregate_fn(first_day, last_day, table) if self.b.find_aggregate_fn else None
        try:
            if existing and not existing.get("stale"):
                build = {
                    "aggregate_table": table,
                    "reused": True,
                    "location": existing.get("location", ""),
                    "execution_id": "",
                    "scanned_bytes": 0,
                    "sql": "",
                    "window": [first_day, last_day],
                }
            else:
                # A window that has not settled (records may still be arriving), or whose registered aggregate
                # was built before it settled, gets a versioned build that is never reused.
                now = _utcnow()
                settled = build_aggregate.window_settled(last_day, self.s.aggregate_settle_minutes, now)
                version = "" if (settled and not existing) else now.strftime("%Y%m%d%H%M%S")
                build = build_aggregate.build_aggregate(
                    self.b.scheme,
                    first_day,
                    last_day,
                    self.b.engine,
                    self.b.log_inventory,
                    agg_database=self.b.agg_database,
                    results_prefix=self.b.results_prefix,
                    dialect=self.b.dialect,
                    version=version,
                )
                build["window_settled"] = settled
                if existing:
                    build["replaces_stale"] = existing["aggregate_table"]
                table = build["aggregate_table"]
            rows = self._rows_for(table, first_day, last_day, build)
        except QuerySkipped:
            if required:
                raise
            return None
        wd = WindowData(first_day, last_day, table, build, rows)
        self.windows[key] = wd
        return wd

    def _rows_for(self, table: str, first_day: str, last_day: str, build: dict) -> list[dict]:
        if self.b.read_parquet_fn is not None:
            loc = build.get("location", "")
            if self.b.find_aggregate_fn:
                # Read where the table actually is: a workgroup that enforces its output location ignores ours.
                found = self.b.find_aggregate_fn(first_day, last_day, table)
                if found:
                    loc = found["location"]
            if loc:
                build["rows_loaded_from"] = loc
                return self.b.read_parquet_fn(loc)
        return self._load_rows(table, first_day, last_day)

    def _load_rows(self, table: str, first_day: str, last_day: str) -> list[dict]:
        database, table = ident(self.b.agg_database), ident(table)
        first_day, last_day = iso_day(first_day), iso_day(last_day)
        sql = f"SELECT * FROM {database}.{table} WHERE day BETWEEN '{first_day}' AND '{last_day}'"  # nosec B608 - names pass ident(); dates are rebuilt by iso_day()
        res = self.b.engine.run(
            sql,
            estimated_bytes=20_000_000,
            label=f"load aggregate {first_day}..{last_day}",
            max_rows=2_000_000,
        )
        return res.rows

    # ---- step: inventory and classification ----------------------------------------------------
    def prepare_inventory(self, rows: list[dict]) -> None:
        if self.b.inventory is not None:
            self.inventory = self.b.inventory
            self.inferred = False
            return
        self.detection = detect_forwarding_interfaces.detect_forwarding_interfaces(
            rows, foreign_share_threshold=self.s.forwarding_foreign_share
        )
        regions = {r["interface_id"]: (r["account_id"], r["region"]) for r in rows}
        self.inventory = Inventory(
            detect_forwarding_interfaces.inferred_inventory_document(self.detection, regions)
        )
        self.inferred = True

    def classify(self, wd: WindowData) -> None:
        res = classify_path.classify_path(wd.rows, self.inventory, inferred=self.inferred)
        wd.classified = res["rows"]
        wd.meta = {
            "methods": res["methods"],
            "traffic_path_crosscheck": res["traffic_path_crosscheck"],
            "traffic_path_disagreements": res.get("traffic_path_disagreements", []),
        }
        remote_ips = {r["remote_addr"] for r in wd.classified if r.get("remote_addr")}
        remote_ips |= {r["srcaddr"] for r in wd.classified if r.get("srcaddr")} | {
            r["dstaddr"] for r in wd.classified if r.get("dstaddr")
        }
        self._classify_destinations(remote_ips, wd.first_day, wd.last_day)
        wd.conversations = enrich_conversations.enrich_conversations(
            pair_conversations.pair_conversations(wd.classified), self.dest_map, self.inventory, self.b.intent
        )

    def _classify_destinations(self, ips: set[str], first_day: str, last_day: str) -> None:
        todo = sorted(ips - set(self.dest_map))
        if not todo:
            return
        inv = None if self.inferred else self.inventory
        first = classify_destination.classify_destination(
            todo,
            inv,
            self.b.intent,
            self.b.ranges,
            home_region=self.b.home_region,
            resolver_names=self.resolver_names,
        )
        if self.b.resolver_fn is not None:
            unresolved = [
                ip for ip, d in first.items() if d["bucket"] in ("aws-hosted-unverified", "other-internet")
            ]
            if unresolved:
                names = self.b.resolver_fn(unresolved, first_day, last_day)
                if isinstance(names, dict):
                    self.resolver_names.update(names)
                    self.resolver_status = f"used ({len(self.resolver_names)} addresses named)"
                    first.update(
                        classify_destination.classify_destination(
                            unresolved,
                            inv,
                            self.b.intent,
                            self.b.ranges,
                            home_region=self.b.home_region,
                            resolver_names=self.resolver_names,
                        )
                    )
                else:
                    self.resolver_status = f"unavailable: {names}"
        self.dest_map.update(first)

    # ---- step: describe ------------------------------------------------------------------------
    def describe(
        self, first_day: str, last_day: str, *, compare_previous: bool = True, generated_at: str = ""
    ) -> dict:
        wd = self.window_data(first_day, last_day)
        _require(wd)
        self.prepare_inventory(wd.rows)
        self.classify(wd)
        provider = self.b.inventory_provider if not self.inferred else "D"
        tier = assign_tier.assign_tier(list(self.b.scheme.fields), provider)
        findings: dict[str, Any] = {
            "meta": self._meta(wd, tier, provider, generated_at),
            "tier": tier,
        }
        findings["integrity"] = self._integrity(wd, first_day, last_day)
        findings["inventory"] = self._inventory_summary()
        nat = self._nat(wd)
        findings["nat"] = nat
        findings["reconciliation"] = self._reconcile(wd, nat)
        findings["path_volume"] = self._path_volume(wd)
        findings["internet_egress"] = self._internet_egress(wd)
        findings["aws_services"] = self._aws_services(wd)
        findings["inter_vpc"] = self._inter_vpc(wd)
        findings["concentration"] = self._concentration(wd)
        findings["time_profile"] = time_profile.time_profile(wd.classified, window_days(first_day, last_day))
        findings["gateways"] = self._gateways(nat)
        findings["rejected"] = self._rejected(wd)
        findings["dependencies"] = self._dependencies(wd)
        findings["endpoint_effectiveness"] = endpoint_effectiveness.endpoint_effectiveness(
            wd.conversations, None if self.inferred else self.inventory
        )
        findings["change"] = (
            self._change(wd, first_day, last_day) if compare_previous else {"status": "not requested"}
        )
        findings["options"] = self._options(wd, findings)
        findings["intent"] = self._intent_status()
        findings["destinations"] = self._destination_summary()
        findings["blind_spots"] = list(BLIND_SPOTS)
        findings["cautions"] = self._cautions(findings)
        findings["headlines"] = self._headlines(findings)
        findings["queries"] = self._queries()
        findings["meta"]["scan"] = self.b.engine.gauge.summary()
        return findings

    # ---- sections ------------------------------------------------------------------------------
    def _meta(self, wd: WindowData, tier: dict, provider: str, generated_at: str) -> dict:
        return {
            "tool": "network-flow-insight",
            "generated_at": generated_at or None,
            "mode": self.b.mode,
            "window": [wd.first_day, wd.last_day],
            "days": len(window_days(wd.first_day, wd.last_day)),
            "tier": tier["tier"],
            "inventory_provider": provider,
            "inventory_note": self.b.provider_note,
            "region": self.b.home_region,
            "raw_table": self.b.scheme.qualified,
            "aggregate_table": f"{self.b.agg_database}.{wd.table}",
            "aggregate_reused": wd.build.get("reused", False),
            # a reused aggregate was built after its window settled
            "window_settled": wd.build.get("window_settled", True),
            "aggregate_rows": len(wd.rows),
            "tables": self.b.tables,
        }

    def _integrity(self, wd: WindowData, first_day: str, last_day: str) -> dict:
        gw_ifaces = []
        if self.inventory and not self.inferred:
            for i in self.inventory.interfaces.values():
                if i["role"] in ("nat-gateway", "interface-endpoint", "transit-gateway"):
                    gw_ifaces.append(
                        {
                            "interface_id": i["id"],
                            "kind": i["role"],
                            "account_id": i.get("account_id"),
                            "gateway_id": self.inventory.nat_for_interface(i["id"]) or i["id"],
                        }
                    )
        s3_parts = self.b.log_inventory.summary()["partitions"]
        out = check_coverage.check_coverage(
            s3_parts,
            self.b.visibility,
            first_day,
            last_day,
            aggregate_rows=wd.rows,
            skipdata_threshold=self.s.skipdata_threshold,
            gateway_interfaces=gw_ifaces or None,
        )
        out["accounts_in_data"] = sorted({r["account_id"] for r in wd.rows})
        out["regions_in_data"] = sorted({r["region"] for r in wd.rows})
        return out

    def _inventory_summary(self) -> dict:
        if self.inferred:
            return {"provider": "D", "note": self.b.provider_note, "detection": self.detection}
        inv = self.inventory
        _require(inv)
        return {
            "provider": self.b.inventory_provider,
            "note": self.b.provider_note,
            "source": inv.source,
            "collected_at": inv.collected_at,
            "vpcs": len(inv.vpcs),
            "subnets": len(inv.subnets),
            "interfaces": len(inv.interfaces),
            "nat_gateways": sorted(inv.nat_gateways),
        }

    def _nat(self, wd: WindowData) -> dict:
        inv = self.inventory
        _require(inv)
        nat_ifaces = inv.nat_interface_ids()
        nat_addrs = sorted(inv.nat_addresses())
        if not nat_ifaces:
            return {"present": False}
        scope = nat_scope.nat_scope(wd.rows, nat_addrs, nat_ifaces)
        leg = nat_leg_check.nat_leg_check(wd.rows, nat_addrs, nat_ifaces, self.s.reconcile_tolerance)
        remote_ips = [r["remote"] for r in scope["remote_rows"]]
        self._classify_destinations(set(remote_ips), wd.first_day, wd.last_day)
        enriched_remote = []
        for r in scope["remote_rows"]:
            d = self.dest_map.get(r["remote"], {})
            enriched_remote.append(
                {
                    **r,
                    "dest_bucket": d.get("bucket", "other-internet"),
                    "dest_service": d.get("service", ""),
                    "dest_region": d.get("region", ""),
                    "dest_name": d.get("name", ""),
                }
            )
        by_bucket = aggregate_by.aggregate_by(
            enriched_remote, ["dest_bucket", "direction"], ["bytes"], counted_only=False
        )
        by_service = aggregate_by.aggregate_by(
            [r for r in enriched_remote if r["dest_bucket"] == "aws-service"],
            ["dest_service", "direction"],
            ["bytes"],
            counted_only=False,
        )
        by_port = aggregate_by.aggregate_by(
            enriched_remote, ["remote_port", "protocol", "direction"], ["bytes"], counted_only=False
        )
        top_remote = top_n.top_n(
            aggregate_by.aggregate_by(
                enriched_remote, ["remote", "dest_bucket", "dest_service"], ["bytes"], counted_only=False
            )["rows"],
            10,
        )
        workload_rows = []
        for w in scope["by_workload"]:
            sub = inv.subnet_for_ip(w["workload"]) if not self.inferred else None
            workload_rows.append(
                {
                    **w,
                    "subnet_id": sub["id"] if sub else None,
                    "vpc_id": inv.vpc_for_ip(w["workload"])["id"]
                    if (not self.inferred and inv.vpc_for_ip(w["workload"]))
                    else None,
                }
            )
        return {
            "present": True,
            "scope": scope,
            "leg_check": leg,
            "by_bucket": by_bucket,
            "by_service": by_service,
            "by_port": by_port,
            "top_remote": top_remote,
            "by_workload": workload_rows,
            "inferred": self.inferred,
        }

    def _reconcile(self, wd: WindowData, nat: dict) -> dict:
        if not nat.get("present"):
            return reconcile.reconcile(leg_check=None, tolerance=self.s.reconcile_tolerance)
        inv = self.inventory
        _require(inv)
        scope = nat["scope"]
        flow_by_gw: dict[str, int] = {}
        for gid, g in inv.nat_gateways.items():
            flow_by_gw[gid] = sum(
                scope["by_interface"].get(i, {}).get("translated_bytes", 0)
                for i in g.get("interface_ids", [])
            )
        metrics: Any = "no metrics source configured"
        if self.b.metrics_fn is not None and not self.inferred:
            gws = [{"kind": "nat", "id": g} for g in sorted(inv.nat_gateways)]
            metrics = self.b.metrics_fn(gws, wd.first_day, wd.last_day)
        cur: Any = None
        flow_cat: dict[str, dict[str, int]] = {}
        accounts = sorted({r["account_id"] for r in wd.rows})
        if self.b.cur_fn is not None:
            cur = self.b.cur_fn(wd.first_day, wd.last_day, accounts)
        flow_cat = self._flow_categories(wd, scope)
        ref = self.b.reference
        flow_ref = {
            "nat_processing": scope["translated"]["total_bytes"],
            "internet_out": sum(flow_cat.get("internet_out", {}).values()),
        }
        r = reconcile.reconcile(
            leg_check=nat["leg_check"],
            flow_by_gateway=flow_by_gw,
            metrics=metrics,
            flow_by_category=flow_cat,
            flow_accounts=accounts,
            cur=cur,
            reference=ref,
            flow_for_reference=flow_ref,
            tolerance=self.s.reconcile_tolerance,
            skipdata_by_gateway=self._skipdata_by_gateway(wd),
        )
        r["flow_by_category"] = flow_cat
        return r

    def _skipdata_by_gateway(self, wd: WindowData) -> dict[str, int]:
        """SKIPDATA records on each NAT gateway's interfaces in the window."""
        inv = self.inventory
        if inv is None:
            return {}
        by_iface: dict[str, int] = {}
        for r in wd.rows:
            if r.get("log_status") == "SKIPDATA":
                by_iface[r["interface_id"]] = by_iface.get(r["interface_id"], 0) + (r.get("records") or 1)
        out = {gid: sum(by_iface.get(i, 0) for i in g.get("interface_ids", [])) for gid, g in inv.nat_gateways.items()}
        return {k: v for k, v in out.items() if v}

    def _flow_categories(self, wd: WindowData, scope: dict) -> dict[str, dict[str, int]]:
        """Flow-derived figures by billing category and account, for the CUR rung."""
        nat_ifaces = set(self.inventory.nat_interface_ids()) if self.inventory else set()
        nat_acct: dict[str, int] = {}
        out_acct: dict[str, int] = {}
        regional: dict[str, int] = {}
        for r in wd.classified:
            if (
                r["interface_id"] in nat_ifaces
                and r.get("path_class") == "nat-translated-leg"
                and r.get("action") == "ACCEPT"
            ):
                nat_acct[r["account_id"]] = nat_acct.get(r["account_id"], 0) + (r.get("bytes") or 0)
        # NAT: CUR NatGateway-Bytes is processed bytes; internet_out: bytes sent to the internet.
        for r in wd.classified:
            if not r.get("counted"):
                continue
            acct = r["account_id"]
            if (
                r["path_class"] in ("internet-nat", "internet-igw")
                and r["direction"] == "out"
                and not is_private(r["dstaddr"] or "")
            ):
                out_acct[acct] = out_acct.get(acct, 0) + (r.get("bytes") or 0)
            if r["path_class"] == "intra-vpc-cross-az":
                regional[acct] = regional.get(acct, 0) + (r.get("bytes") or 0)
        return {"nat_processing": nat_acct, "internet_out": out_acct, "regional": regional}

    def _path_volume(self, wd: WindowData) -> dict:
        by_path = aggregate_by.aggregate_by(
            [
                {
                    **c,
                    "bytes": c["total_bytes"],
                    "records": c["records"],
                    "c2s": c["c2s_bytes"],
                    "s2c": c["s2c_bytes"],
                }
                for c in wd.conversations
                if c["action"] == "ACCEPT"
            ],
            ["path_class"],
            ["bytes", "c2s", "s2c", "records"],
            counted_only=False,
        )
        methods: dict[str, set[str]] = {}
        for r in counted_rows(wd.classified):
            methods.setdefault(r["path_class"], set()).add(r["method"])
        for row in by_path["rows"]:
            row["methods"] = sorted(methods.get(row["path_class"], []))
        counted_total = sum(
            r.get("bytes") or 0 for r in counted_rows(wd.classified) if r.get("action") == "ACCEPT"
        )
        by_dir = aggregate_by.aggregate_by(
            [r for r in wd.classified if r.get("counted") and r.get("action") == "ACCEPT"],
            ["path_class", "direction"],
            ["bytes"],
            counted_only=False,
        )
        return {
            "by_path": by_path,
            "by_path_and_row_direction": by_dir,
            "counted_total_bytes": counted_total,
            "crosscheck_traffic_path": wd.meta.get("traffic_path_crosscheck", {}),
            "crosscheck_disagreements": wd.meta.get("traffic_path_disagreements", []),
            "methods_by_records": wd.meta.get("methods", {}),
        }

    def _internet_egress(self, wd: WindowData) -> dict:
        convs = [
            c
            for c in wd.conversations
            if c["path_class"] in INTERNET_PATHS and c["egress"] and c["action"] == "ACCEPT"
        ]
        rows = [
            {**c, "bytes": c["total_bytes"], "out": c["c2s_bytes"], "back": c["s2c_bytes"]} for c in convs
        ]
        return {
            "by_bucket": aggregate_by.aggregate_by(
                rows, ["dest_bucket"], ["bytes", "out", "back"], counted_only=False
            ),
            "by_service": aggregate_by.aggregate_by(
                [r for r in rows if r["dest_bucket"] == "aws-service"],
                ["dest_service", "path_class"],
                ["bytes", "out", "back"],
                counted_only=False,
            ),
            "by_port": aggregate_by.aggregate_by(
                rows, ["protocol", "port"], ["bytes", "out", "back"], counted_only=False
            ),
            "top_destinations": top_n.top_n(
                aggregate_by.aggregate_by(
                    rows,
                    ["server", "dest_bucket", "dest_service", "dest_name"],
                    ["bytes", "out", "back"],
                    counted_only=False,
                )["rows"],
                10,
            ),
            "total_bytes": sum(r["bytes"] for r in rows),
        }

    def _aws_services(self, wd: WindowData) -> dict:
        convs = [
            {**c, "bytes": c["total_bytes"]}
            for c in wd.conversations
            if c["dest_bucket"] == "aws-service" and c["egress"] and c["action"] == "ACCEPT"
        ]
        return {
            "by_service_and_path": aggregate_by.aggregate_by(
                convs, ["dest_service", "path_class"], ["bytes"], counted_only=False
            ),
            "total_bytes": sum(c["bytes"] for c in convs),
        }

    def _inter_vpc(self, wd: WindowData) -> dict:
        paths = (
            "transit-gateway",
            "vpc-peering",
            "cross-region",
            "vgw-dx",
            "intra-vpc-cross-az",
            "intra-vpc-same-az",
        )
        convs = [
            {**c, "bytes": c["total_bytes"]}
            for c in wd.conversations
            if c["path_class"] in paths and c["action"] == "ACCEPT"
        ]
        return {
            "by_path": aggregate_by.aggregate_by(convs, ["path_class"], ["bytes"], counted_only=False),
            "by_pair": aggregate_by.aggregate_by(
                convs, ["consumer", "dest_bucket", "dest_name", "path_class"], ["bytes"], counted_only=False
            ),
            "total_bytes": sum(c["bytes"] for c in convs),
        }

    def _concentration(self, wd: WindowData) -> dict:
        rows = [r for r in wd.classified if r.get("counted") and r.get("action") == "ACCEPT"]
        out: dict[str, Any] = {}
        for name, dim in (("by_account", "account_id"), ("by_region", "region"), ("by_vpc", "vpc_id")):
            out[name] = top_n.top_n(
                aggregate_by.aggregate_by(rows, [dim], ["bytes"], counted_only=False)["rows"], 10
            )
        convs = [
            {**c, "bytes": c["total_bytes"]}
            for c in wd.conversations
            if c["egress"] and c["action"] == "ACCEPT"
        ]
        out["by_workload"] = top_n.top_n(
            aggregate_by.aggregate_by(convs, ["client"], ["bytes"], counted_only=False)["rows"], 10
        )
        return out

    def _gateways(self, nat: dict) -> dict:
        if not nat.get("present"):
            return {"present": False}
        return gateway_utilisation.gateway_utilisation(
            nat["scope"], None if self.inferred else self.inventory, self.s.idle_gateway_bytes
        )

    def _rejected(self, wd: WindowData) -> dict:
        rej = [r for r in wd.classified if r.get("action") == "REJECT" and r.get("log_status") == "OK"]
        return {
            "total_bytes": sum(r.get("bytes") or 0 for r in rej),
            "records": sum(r.get("records") or 0 for r in rej),
            "by_source": top_n.top_n(
                aggregate_by.aggregate_by(rej, ["srcaddr"], ["bytes", "records"], counted_only=False)["rows"],
                10,
                "records",
            ),
            "by_destination": top_n.top_n(
                aggregate_by.aggregate_by(rej, ["dstaddr"], ["bytes", "records"], counted_only=False)["rows"],
                10,
                "records",
            ),
            "by_port": top_n.top_n(
                aggregate_by.aggregate_by(
                    rej, ["protocol", "dstport"], ["bytes", "records"], counted_only=False
                )["rows"],
                10,
                "records",
            ),
        }

    def _dependencies(self, wd: WindowData) -> dict:
        edges: dict[tuple, dict] = {}
        for c in wd.conversations:
            if not c["egress"] or c["action"] != "ACCEPT":
                continue
            k = (c["consumer"], c["provider"][0], c["provider"][1], c["port"])
            e = edges.setdefault(
                k,
                {
                    "consumer": k[0],
                    "provider_bucket": k[1],
                    "provider": k[2],
                    "port": k[3],
                    "bytes": 0,
                    "conversations": 0,
                    "paths": set(),
                },
            )
            e["bytes"] += c["total_bytes"]
            e["conversations"] += 1
            e["paths"].add(c["path_class"])
        rows = []
        for e in sorted(edges.values(), key=lambda e: (-e["bytes"], e["consumer"], e["provider"], e["port"])):
            rows.append({**e, "paths": sorted(e["paths"])})
        return {"edges": rows}

    def _change(self, wd: WindowData, first_day: str, last_day: str) -> dict:
        n_days = len(window_days(first_day, last_day))
        prev_last = (date.fromisoformat(first_day) - timedelta(days=1)).isoformat()
        prev_first = (date.fromisoformat(first_day) - timedelta(days=n_days)).isoformat()
        prev = self.window_data(prev_first, prev_last, required=False)
        if prev is None:
            return {
                "status": "skipped",
                "why": "previous window scan was skipped by the cost gauge",
                "previous_window": [prev_first, prev_last],
            }
        if not prev.rows:
            return {"status": "no-data", "previous_window": [prev_first, prev_last]}
        self.classify(prev)

        def table(w: WindowData, dims: list[str]) -> list[dict]:
            rows = [{**c, "bytes": c["total_bytes"]} for c in w.conversations if c["action"] == "ACCEPT"]
            return aggregate_by.aggregate_by(rows, dims, ["bytes"], counted_only=False)["rows"]

        out: dict[str, Any] = {"status": "available", "previous_window": [prev_first, prev_last]}
        out["by_path"] = period_compare.period_compare(
            table(wd, ["path_class"]), table(prev, ["path_class"]), ["path_class"]
        )
        out["by_destination"] = period_compare.period_compare(
            table(wd, ["dest_bucket", "dest_service"]),
            table(prev, ["dest_bucket", "dest_service"]),
            ["dest_bucket", "dest_service"],
        )
        out["by_conversation"] = period_compare.period_compare(
            table(wd, ["consumer", "server", "port"]),
            table(prev, ["consumer", "server", "port"]),
            ["consumer", "server", "port"],
        )
        out["previous_aggregate"] = {"table": prev.table, "execution_id": prev.build.get("execution_id", "")}
        return out

    def _options(self, wd: WindowData, f: dict) -> dict:
        volumes = {r["path_class"]: r["bytes"] for r in f["path_volume"]["by_path"]["rows"]}
        ee = f["endpoint_effectiveness"]
        evidence = {
            "gateway_route_bytes": sum(
                x["bytes_on_nat"] for x in ee.get("missing_gateway_route_findings", [])
            ),
            "interface_endpoint_bytes": sum(
                x["bytes_on_nat"] for x in ee.get("interface_endpoint_findings", [])
            ),
            "cross_region_bytes": sum(x["bytes_on_nat"] for x in ee.get("cross_region_findings", [])),
            "internet_nat_by_bucket": {
                r["dest_bucket"]: r["bytes"] for r in f["internet_egress"]["by_bucket"]["rows"] if r["bytes"]
            },
        }
        return price_context.price_context(volumes, self.b.rates, evidence)

    def _intent_status(self) -> dict:
        i = self.b.intent
        if i is None or not i.baseline:
            return {
                "baseline": False,
                "networks": len(i.networks) if i else 0,
                "note": "No committed baseline; describe mode applies. A baseline can be drafted from this run.",
            }
        return {"baseline": True, "entries": len(i.baseline), "networks": len(i.networks)}

    def _destination_summary(self) -> dict:
        counts: dict[str, int] = {}
        for d in self.dest_map.values():
            counts[d["bucket"]] = counts.get(d["bucket"], 0) + 1
        return {
            "addresses_by_bucket": dict(sorted(counts.items())),
            "resolver": self.resolver_status,
            "ip_ranges_sync": self.b.ranges.sync_token,
        }

    def _cautions(self, f: dict) -> list[str]:
        c: list[str] = []
        if not f["meta"].get("window_settled", True):
            c.append(
                "The window has not settled: flow records reach S3 minutes after capture (allow up to "
                f"{self.s.aggregate_settle_minutes} minutes after the last day ends), so totals are provisional. "
                "Gateway metrics run ahead of the delivered records, so the gateway-metrics rung reads low. "
                "Re-run after the window settles for final figures; this aggregate will not be reused."
            )
        integ = f["integrity"]
        if integ.get("missing_partitions"):
            c.append(
                f"The table cannot see {len(integ['missing_partitions'])} partition(s) present in S3 "
                f"(accounts {integ['missing_accounts']}, {integ['missing_bytes']} bytes); they are excluded from every total."
            )
        ls = integ.get("log_status")
        if ls and ls["caution"]:
            c.append(
                f"SKIPDATA records are {ls['skipdata_share_pct']}% of records (threshold {ls['threshold_pct']}%); totals on affected interfaces are low."
            )
        if integ.get("gateway_interfaces_without_records"):
            c.append(
                "Gateway interfaces with no records in the window (idle, or no flow log attached): "
                + ", ".join(g["interface_id"] for g in integ["gateway_interfaces_without_records"])
            )
        rec = f["reconciliation"]
        if rec.get("shares_caution"):
            c.append("NAT composition shares carry a caution: " + rec["shares_caution"])
        dis = f["path_volume"].get("crosscheck_disagreements") or []
        if dis:
            from .core.units import fmt_bytes

            parts = "; ".join(
                f"{d['subnet_id'] or 'unknown subnet'}: classified {d['path_class']} from current routes, "  # one message split over two f-strings, no missing comma  # nosemgrep: string-concat-in-list
                f"record says {d['traffic_path_class']} ({d['records']} records, {fmt_bytes(d['bytes'])})"
                for d in dis[:3]
            )
            c.append(
                "Some records' own traffic-path contradicts the current route tables, so a route probably changed "
                "during the window (or the inventory is not from the window); their path class comes from the "
                f"current routes. {parts}."
            )
        if self.inferred:
            c.append(
                "No inventory provider: forwarding interfaces and their roles are inferred from the data and labelled inferred."
            )
        if f["tier"]["tier"] != "full":
            c.append(
                f"Capability tier is {f['tier']['tier']}: some sections are inferred or unavailable (see the tier table)."
            )
        skipped = [e for e in self.b.engine.gauge.ledger if e.skipped]
        if skipped:
            c.append(
                f"{len(skipped)} query(ies) were skipped by the cost gauge: "
                + "; ".join(sorted({e.reason for e in skipped}))
            )
        if f["change"].get("status") in ("skipped", "no-data"):
            c.append(
                "The previous-window comparison is not available: "
                + str(f["change"].get("why", f["change"]["status"]))
            )
        return c

    def _headlines(self, f: dict) -> list[str]:
        from .core.units import fmt_bytes

        h: list[str] = []
        pv = {r["path_class"]: r for r in f["path_volume"]["by_path"]["rows"]}
        total = f["path_volume"]["by_path"]["total"]["bytes"]
        if "internet-nat" in pv:
            r = pv["internet-nat"]
            h.append(
                f"{fmt_bytes(r['bytes'])} ({share(r['bytes'], total)}% of counted traffic) reached the internet or AWS public endpoints through NAT gateways."
            )
        ee = f["endpoint_effectiveness"]
        miss = ee.get("missing_gateway_route_findings", [])
        if miss:
            h.append(
                f"{fmt_bytes(sum(m['bytes_on_nat'] for m in miss))} of S3 and DynamoDB traffic crossed NAT from subnets without a gateway-endpoint route ({', '.join(sorted({m['subnet_id'] for m in miss}))})."
            )
        ie = ee.get("interface_endpoint_findings", [])
        if ie:
            h.append(
                f"{fmt_bytes(sum(x['bytes_on_nat'] for x in ie))} reached a service that has an interface endpoint in the VPC by crossing NAT instead ({', '.join(x['endpoint_id'] for x in ie)})."
            )
        xr = ee.get("cross_region_findings", [])
        if xr:
            h.append(
                f"{fmt_bytes(sum(x['bytes_on_nat'] for x in xr))} went to S3 or DynamoDB in another Region over NAT."
            )
        top = f["internet_egress"]["top_destinations"]["rows"]
        if top:
            t = top[0]
            label = t.get("dest_service") or t.get("dest_name") or t["dest_bucket"]
            h.append(
                f"The largest internet-path destination was {t['server']} ({label}), {fmt_bytes(t['bytes'])}."
            )
        chg = f["change"]
        if chg.get("status") == "available":
            tot = chg["by_path"]["totals"]
            h.append(
                f"Counted traffic changed by {fmt_bytes(tot['delta'])} ({tot['change_pct']}%) against the previous equal window; "
                f"{len(chg['by_conversation']['new'])} new and {len(chg['by_conversation']['gone'])} vanished conversations."
            )
        rej = f["rejected"]
        if rej["records"]:
            h.append(f"{rej['records']} flow records ({fmt_bytes(rej['total_bytes'])}) were rejected.")
        return h[:5]

    def _queries(self) -> list[dict]:
        return [
            {
                "label": e.label,
                "execution_id": e.execution_id,
                "scanned_bytes": e.scanned_bytes,
                "estimated_bytes": e.estimated_bytes,
                "cost_usd": round(e.cost_usd, 4),
                "skipped": e.skipped,
                "reason": e.reason,
                "sql": e.sql,
            }
            for e in self.b.engine.gauge.ledger
        ]

    # ---- intent lifecycle ----------------------------------------------------------------------
    def intent_draft(self, first_day: str, last_day: str) -> dict:
        wd = self.window_data(first_day, last_day)
        _require(wd)
        if not wd.conversations:
            self.prepare_inventory(wd.rows)
            self.classify(wd)
        return draft_intent.draft_intent(wd.conversations, self.dest_map, self.b.intent)

    def intent_drift(self, first_day: str, last_day: str) -> dict:
        wd = self.ready(first_day, last_day)
        return drift.drift(wd.conversations, self._baseline())

    def intent_what_if(self, first_day: str, last_day: str) -> dict:
        wd = self.ready(first_day, last_day)
        return what_if.what_if(wd.conversations, self._baseline())

    def ready(self, first_day: str, last_day: str) -> WindowData:
        wd = self.window_data(first_day, last_day)
        _require(wd)
        if not wd.conversations:
            self.prepare_inventory(wd.rows)
            self.classify(wd)
        return wd

    def _baseline(self) -> Intent:
        if self.b.intent is None:
            return Intent()
        return self.b.intent
