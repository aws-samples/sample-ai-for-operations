# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: render the layered report and data pack from the findings.

Every figure in the output is formatted from a value a precision tool produced. Formatting never computes:
bytes become labelled decimal units, and percentages are the ones the tools returned. Model-written
interpretation, when supplied, is rendered in a clearly marked block and carries no figures of its own.
"""

from __future__ import annotations

import csv
import html
import io
import json
import logging
import math
from typing import Any

from ..core.grounding import ungrounded
from ..core.units import fmt_bytes
from .nat_scope import translated_leg_sql

logger = logging.getLogger(__name__)

Block = tuple  # ("h1"|"h2"|"h3"|"p"|"note"|"caution"|"ul"|"table"|"svg"|"code", ...)


def _b(v: Any) -> str:
    return fmt_bytes(v) if isinstance(v, int | float) else str(v)


def _pct(v: Any) -> str:
    return "n/a" if v is None else f"{v}%"


def _ratio(v: Any) -> str:
    return "n/a" if v is None else f"{v:.4f}"


def _cell(v: Any) -> str:
    return "" if v is None else str(v)


def render_report(findings: dict, narrative: dict[str, str] | None = None) -> dict[str, str]:
    """Render the report. Interpretation text is kept only if every figure in it appears in the findings."""
    accepted: dict[str, str] = {}
    rejected: list[str] = []
    for key, text in (narrative or {}).items():
        bad = ungrounded(str(text), findings)
        if bad:
            logger.warning(
                json.dumps({"event": "narrative_rejected", "section": key, "ungrounded": bad[:10]})
            )
            rejected.append(
                f"Interpretation for '{key}' was left out because it contained figures that are not in the findings."
            )
        else:
            accepted[key] = str(text)
    blocks = _blocks(findings, accepted)
    if rejected:
        blocks[1:1] = [("caution", rejected)]
    svg = _diagram(findings["dependencies"]["edges"])
    blocks_with_svg = [(*b[:1], svg) if b[0] == "svg" else b for b in blocks]
    return {
        "report.md": _to_md(blocks_with_svg),
        "report.html": _to_html(blocks_with_svg, findings),
        "diagram.svg": svg,
        "data/series.csv": _series_csv(findings),
        "data/edges.csv": _edges_csv(findings["dependencies"]["edges"]),
        "data/findings.json": json.dumps(findings, indent=2, sort_keys=True, default=str),
        "data/aggregate_manifest.json": json.dumps(_manifest(findings), indent=2, sort_keys=True),
    }


# ------------------------------------------------------------------------------ content


def _blocks(f: dict, nar: dict[str, str]) -> list[Block]:
    m = f["meta"]
    out: list[Block] = [("h1", "Network flow insight: where does the data go?")]
    out += _summary(f)
    out += _interp(nar, "summary")
    out += [("h2", "1. Coverage and integrity")] + _integrity(f) + _interp(nar, "integrity")
    out += [("h2", "2. Volume by path class")] + _paths(f) + _interp(nar, "paths")
    out += [("h2", "3. Internet egress")] + _egress(f) + _interp(nar, "egress")
    out += [("h2", "4. AWS services and how they were reached")] + _services(f) + _interp(nar, "services")
    out += [("h2", "5. Inter-VPC and cross-Region traffic")] + _inter(f) + _interp(nar, "inter_vpc")
    out += [("h2", "6. NAT gateway traffic")] + _nat(f) + _interp(nar, "nat")
    out += [("h2", "7. Concentration")] + _concentration(f) + _interp(nar, "concentration")
    out += [("h2", "8. Time profile")] + _time(f) + _interp(nar, "time")
    out += [("h2", "9. Gateway inventory")] + _gateways(f)
    out += [("h2", "10. Rejected flows")] + _rejected(f)
    out += [("h2", "11. What changed against the previous equal window")] + _change(f)
    out += [
        ("h2", "12. Dependency view"),
        (
            "p",
            "Consumers on the left, providers on the right; line weight follows bytes. The same edges are in data/edges.csv.",
        ),
        ("svg", ""),
    ]
    out += [("h2", "13. Reconciliation")] + _recon(f)
    out += [("h2", "14. Architecture options the evidence supports")] + _options(f) + _interp(nar, "options")
    out += [("h2", "Appendix A. Capability tier and sections")] + _tier(f)
    out += [("h2", "Appendix B. Methodology")] + _method(f)
    out += [("h2", "Appendix C. Blind spots"), ("ul", f["blind_spots"])]
    out += [("h2", "Appendix D. Reproducibility")] + _repro(f)
    out += [
        (
            "note",
            f"Window {m['window'][0]} to {m['window'][1]}. Tier {m['tier']}, inventory provider {m['inventory_provider']}.",
        )
    ]
    return out


def _interp(nar: dict[str, str], key: str) -> list[Block]:
    if key in nar and nar[key].strip():
        return [
            ("note", "Interpretation (written by the model; every figure it refers to is in the tables):"),
            ("p", nar[key].strip()),
        ]
    return []


def _summary(f: dict) -> list[Block]:
    m, rec = f["meta"], f["reconciliation"]
    scan = m["scan"] if "scan" in m else {}
    rows = [
        ["Window", f"{m['window'][0]} to {m['window'][1]} ({m['days']} days)"],
        ["Capability tier", m["tier"]],
        ["Inventory provider", f"{m['inventory_provider']} ({m['inventory_note']})"],
        ["Raw flow-log table", m["raw_table"]],
        ["Aggregate table", f"{m['aggregate_table']}{' (reused)' if m['aggregate_reused'] else ''}"],
        [
            "Scanned",
            f"{_b(scan.get('scanned_bytes', 0))} in {scan.get('queries', 0)} queries; estimated cost USD {scan.get('cost_usd', 0)}",
        ],
        ["Reconciliation", f"{rec['verdict']} (rungs used: {rec['rungs_used'] or 'none'})"],
        ["Mode", m["mode"]],
    ]
    out: list[Block] = [("h2", "Summary"), ("table", ["Item", "Value"], rows)]
    if f["headlines"]:
        out += [("h3", "Headline findings"), ("ul", f["headlines"])]
    if f["cautions"]:
        out += [("h3", "Cautions"), ("caution", f["cautions"])]
    out.append(
        (
            "note",
            "This is an evidence pack for a governance conversation. It is not an attestation and does not claim completeness.",
        )
    )
    return out


def _integrity(f: dict) -> list[Block]:
    i = f["integrity"]
    rows = [
        ["Partitions in S3 for the window", i["s3_partitions"]],
        ["Partitions the table can see", i["visible_partitions"]],
        ["Missing from the table", len(i["missing_partitions"])],
        ["Accounts in the data", ", ".join(i["accounts_in_data"])],
        ["Regions in the data", ", ".join(i["regions_in_data"])],
        ["Days with no data in S3", ", ".join(i["days_without_any_data"]) or "none"],
    ]
    ls = i.get("log_status")
    if ls:
        rows += [
            ["Records in window", ls["total_records"]],
            ["SKIPDATA records", f"{ls['skipdata_records']} ({_pct(ls['skipdata_share_pct'])})"],
            ["NODATA records", f"{ls['nodata_records']} ({_pct(ls['nodata_share_pct'])})"],
        ]
    out: list[Block] = [("table", ["Check", "Result"], rows)]
    if i["missing_partitions"]:
        out += [
            (
                "caution",
                [
                    "These partitions exist in S3 but the table cannot see them. They are excluded from every figure below."
                ],
            ),
            (
                "table",
                ["Account", "Region", "Day", "Bytes in S3"],
                [[p["account_id"], p["region"], p["day"], _b(p["bytes"])] for p in i["missing_partitions"]],
            ),
        ]
    if i.get("gateway_interfaces_without_records"):
        out += [
            (
                "p",
                "Gateway interfaces with no records in the window (idle, or no flow log attached): "
                + ", ".join(g["interface_id"] for g in i["gateway_interfaces_without_records"]),
            )
        ]
    if i.get("accounts_with_gateways_but_no_flow_log"):
        out += [
            (
                "caution",
                [
                    "Accounts with gateways but no flow-log partition in the table: "
                    + ", ".join(i["accounts_with_gateways_but_no_flow_log"])
                ],
            )
        ]
    return out


def _paths(f: dict) -> list[Block]:
    pv = f["path_volume"]
    rows = [
        [
            r["path_class"],
            _b(r["bytes"]),
            _pct(r["bytes_share_pct"]),
            _b(r["c2s"]),
            _b(r["s2c"]),
            r["records"],
            ", ".join(r.get("methods", [])),
        ]
        for r in pv["by_path"]["rows"]
    ]
    rows.append(
        [
            "Total counted",
            _b(pv["by_path"]["total"]["bytes"]),
            "100%",
            _b(pv["by_path"]["total"]["c2s"]),
            _b(pv["by_path"]["total"]["s2c"]),
            pv["by_path"]["total"]["records"],
            "",
        ]
    )
    out: list[Block] = [
        (
            "p",
            "Each byte is counted once, at the interface that sent it. Client-to-server is the direction the conversation was opened in; server-to-client is the return.",
        ),
        (
            "table",
            [
                "Path class",
                "Bytes",
                "Share",
                "Client to server",
                "Server to client",
                "Records",
                "Classified by",
            ],
            rows,
        ),
    ]
    cc = pv.get("crosscheck_traffic_path")
    if cc:
        out.append(
            (
                "p",
                f"Cross-check against the traffic-path field: {cc.get('agree', 0)} records agree, {cc.get('disagree', 0)} disagree.",
            )
        )
    return out


def _egress(f: dict) -> list[Block]:
    e = f["internet_egress"]
    return [
        ("p", f"Conversations on internet-facing paths: {_b(e['total_bytes'])} in total."),
        ("h3", "By destination bucket"),
        (
            "table",
            ["Bucket", "Total", "Share", "Sent", "Returned"],
            [
                [r["dest_bucket"], _b(r["bytes"]), _pct(r["bytes_share_pct"]), _b(r["out"]), _b(r["back"])]
                for r in e["by_bucket"]["rows"]
            ],
        ),
        ("h3", "By AWS service"),
        (
            "table",
            ["Service", "Path", "Total", "Sent", "Returned"],
            [
                [r["dest_service"], r["path_class"], _b(r["bytes"]), _b(r["out"]), _b(r["back"])]
                for r in e["by_service"]["rows"]
            ],
        ),
        ("h3", "By protocol and port"),
        (
            "table",
            ["Protocol", "Port", "Total", "Share"],
            [
                [r["protocol"], r["port"], _b(r["bytes"]), _pct(r["bytes_share_pct"])]
                for r in e["by_port"]["rows"][:15]
            ],
        ),
        ("h3", "Largest destinations"),
        (
            "table",
            ["Address", "Bucket", "Service", "Name", "Total"],
            [
                [r["server"], r["dest_bucket"], r["dest_service"], r["dest_name"], _b(r["bytes"])]
                for r in e["top_destinations"]["rows"]
            ],
        ),
    ]


def _services(f: dict) -> list[Block]:
    s = f["aws_services"]
    out: list[Block] = [
        (
            "table",
            ["Service", "Reached via", "Bytes", "Share"],
            [
                [r["dest_service"], r["path_class"], _b(r["bytes"]), _pct(r["bytes_share_pct"])]
                for r in s["by_service_and_path"]["rows"]
            ],
        ),
    ]
    ee = f["endpoint_effectiveness"]
    if ee.get("status") != "available":
        return out + [("p", f"Endpoint effectiveness is unavailable: {ee.get('why', '')}")]
    if ee["interface_endpoint_findings"]:
        out += [
            ("h3", "Interface endpoints whose service traffic still crosses NAT"),
            (
                "table",
                ["Endpoint", "Service", "Bytes on NAT", "Subnets", "Likely causes"],
                [
                    [
                        x["endpoint_id"],
                        x["service"],
                        _b(x["bytes_on_nat"]),
                        ", ".join(f"{k}: {_b(v)}" for k, v in x["by_subnet"].items()),
                        "; ".join(x["likely_causes"]),
                    ]
                    for x in ee["interface_endpoint_findings"]
                ],
            ),
        ]
    if ee["missing_gateway_route_findings"]:
        out += [
            ("h3", "Subnets whose S3 or DynamoDB traffic crosses NAT without a gateway-endpoint route"),
            (
                "table",
                ["Subnet", "Service", "Bytes on NAT", "Workloads", "Observation"],
                [
                    [
                        x["subnet_id"],
                        x["service"],
                        _b(x["bytes_on_nat"]),
                        ", ".join(x["workloads"]),
                        x["observation"],
                    ]
                    for x in ee["missing_gateway_route_findings"]
                ],
            ),
        ]
    if ee["cross_region_findings"]:
        out += [
            ("h3", "S3 or DynamoDB in another Region over NAT"),
            (
                "table",
                ["Service", "Destination Region", "Bytes on NAT", "Workloads"],
                [
                    [x["service"], x["destination_region"], _b(x["bytes_on_nat"]), ", ".join(x["workloads"])]
                    for x in ee["cross_region_findings"]
                ],
            ),
        ]
    if not (
        ee["interface_endpoint_findings"]
        or ee["missing_gateway_route_findings"]
        or ee["cross_region_findings"]
    ):
        out.append(("p", "No endpoint-effectiveness findings in this window."))
    return out


def _inter(f: dict) -> list[Block]:
    i = f["inter_vpc"]
    return [
        (
            "table",
            ["Path", "Bytes", "Share"],
            [[r["path_class"], _b(r["bytes"]), _pct(r["bytes_share_pct"])] for r in i["by_path"]["rows"]],
        ),
        (
            "table",
            ["Consumer", "Destination bucket", "Destination", "Path", "Bytes"],
            [
                [r["consumer"], r["dest_bucket"], r["dest_name"], r["path_class"], _b(r["bytes"])]
                for r in i["by_pair"]["rows"][:20]
            ],
        ),
    ]


def _nat(f: dict) -> list[Block]:
    n, rec = f["nat"], f["reconciliation"]
    if not n.get("present"):
        return [("p", "No NAT gateway interfaces were found in the data or the inventory.")]
    s, leg = n["scope"], n["leg_check"]
    t, u = s["translated"], s["untranslated"]
    out: list[Block] = []
    if n.get("inferred"):
        out.append(("caution", ["NAT gateways are inferred from the data (provider D)."]))
    out += [
        (
            "p",
            "Measured on the gateway interfaces. A NAT gateway's address is on every record it logs; the translated "  # one paragraph split over several strings, no missing comma  # nosemgrep: string-concat-in-list
            "leg is the internet side (NAT address to and from the destination), the untranslated leg the workload "
            "side (workload to and from the NAT address). Totals count the translated leg only, so each byte counts "
            f"once. Leg told by: {s.get('leg_rule', 'pkt-* fields')}. NAT addresses used: {', '.join(s['nat_addresses'])}.",
        ),
        (
            "table",
            ["Measure", "Bytes"],
            [
                ["Translated leg, total", _b(t["total_bytes"])],
                ["Outbound to destinations", _b(t["out_bytes"])],
                ["Return from destinations", _b(t["in_bytes"])],
                ["Untranslated leg, total", _b(u["total_bytes"])],
                ["Unmatched (no known NAT address)", _b(s.get("unmatched", {}).get("total_bytes", 0))],
                [
                    "Unsolicited inbound to the NAT addresses (never translated; not in any total)",
                    _b(s.get("unsolicited", {}).get("total_bytes", 0)),
                ],
            ],
        ),
        (
            "p",
            f"Reconciliation: {rec['verdict']}. Leg check ratio {_ratio(leg['overall']['ratio'])} ({leg['overall']['explanation']}); rungs used {rec['rungs_used']}.",
        ),
    ]
    if rec["show_shares"] and not rec["shares_caution"]:
        out += _nat_shares(n)
    elif rec["show_shares"]:
        out += [("caution", ["Shares shown with a caution: " + rec["shares_caution"]])] + _nat_shares(n)
    else:
        out += [
            (
                "caution",
                [
                    "NAT composition shares are withheld: no reconciliation rung confirmed the total. "
                    + (rec["shares_caution"] or "")
                ],
            )
        ]
    out += [
        ("h3", "Attribution to workloads (" + s["attribution_method"] + ")"),
        (
            "table",
            ["Workload", "Subnet", "Outbound", "Return", "Total"],
            [
                [
                    w["workload"],
                    w.get("subnet_id") or "",
                    _b(w["out_bytes"]),
                    _b(w["in_bytes"]),
                    _b(w["total_bytes"]),
                ]
                for w in n["by_workload"]
            ],
        ),
    ]
    return out


def _nat_shares(n: dict) -> list[Block]:
    return [
        ("h3", "Composition by destination bucket and direction"),
        (
            "table",
            ["Bucket", "Direction", "Bytes", "Share"],
            [
                [r["dest_bucket"], r["direction"], _b(r["bytes"]), _pct(r["bytes_share_pct"])]
                for r in n["by_bucket"]["rows"]
            ],
        ),
        ("h3", "AWS services over NAT"),
        (
            "table",
            ["Service", "Direction", "Bytes", "Share"],
            [
                [r["dest_service"], r["direction"], _b(r["bytes"]), _pct(r["bytes_share_pct"])]
                for r in n["by_service"]["rows"]
            ],
        ),
    ]


def _concentration(f: dict) -> list[Block]:
    c = f["concentration"]
    out: list[Block] = []
    for key, title, dim in (
        ("by_account", "Accounts (bytes sent)", "account_id"),
        ("by_region", "Regions (bytes sent)", "region"),
        ("by_vpc", "VPCs (bytes sent)", "vpc_id"),
        ("by_workload", "Workloads (conversations they opened, both directions)", "client"),
    ):
        out += [
            ("h3", title),
            (
                "table",
                ["Name", "Bytes", "Share of counted traffic"],
                [
                    [_cell(r[dim]), _b(r["bytes"]), _pct(r["bytes_share_of_total_pct"])]
                    for r in c[key]["rows"]
                ],
            ),
        ]
    chg = f["change"]
    if chg.get("status") == "available":
        g = chg["by_conversation"]
        out += [
            ("h3", "Largest contributors to growth (conversations)"),
            (
                "table",
                ["Consumer", "Server", "Port", "Change", "Share of growth"],
                [
                    [r["consumer"], r["server"], r["port"], _b(r["delta"]), _pct(r["share_of_growth_pct"])]
                    for r in g["rows"]
                    if r["delta"] > 0
                ][:10],
            ),
        ]
    return out


def _time(f: dict) -> list[Block]:
    t = f["time_profile"]
    out: list[Block] = [
        (
            "table",
            ["Day", "Weekday", "Bytes"],
            [[s["day"], s["weekday"], _b(s["bytes"])] for s in t["series"]],
        ),
        (
            "p",
            f"Weekday mean {_b(t['weekday_mean_bytes'])} over {t['weekday_days']} days; weekend mean {_b(t['weekend_mean_bytes'])} over {t['weekend_days']} days. "  # one paragraph split over two f-strings, no missing comma  # nosemgrep: string-concat-in-list
            f"Peak day {t['peak_day']['day']} ({_b(t['peak_day']['bytes'])}).",
        ),
    ]
    if t["hourly_available"]:
        ph = t["peak_hour_of_window"]
        out.append(
            (
                "p",
                f"Peak hour of the window: {ph['day']} {ph['hour']:02d}:00 UTC ({_b(ph['bytes'])}). Busiest hour of day across the window: {t['peak_hour_of_day']['hour']:02d}:00 UTC ({_b(t['peak_hour_of_day']['bytes'])}).",
            )
        )
    else:
        out.append(("p", "Hourly profile is unavailable in this data."))
    return out


def _gateways(f: dict) -> list[Block]:
    g = f["gateways"]
    if not g.get("present", True):
        return [("p", "No NAT gateways found.")]
    out: list[Block] = [
        (
            "table",
            ["Gateway", "VPC", "Bytes in window", "Status"],
            [
                [x["gateway_id"], x.get("vpc_id") or "", _b(x["translated_bytes"]), x["status"]]
                for x in g["gateways"]
            ],
        )
    ]
    if g["idle_or_near_idle"]:
        out.append(
            ("p", "Idle or near-idle (below the configured threshold): " + ", ".join(g["idle_or_near_idle"]))
        )
    return out


def _rejected(f: dict) -> list[Block]:
    r = f["rejected"]
    if not r["records"]:
        return [("p", "No rejected flows in the window.")]
    return [
        ("p", f"{r['records']} rejected records, {_b(r['total_bytes'])}. Described, not judged."),
        ("table", ["Source", "Records"], [[x["srcaddr"], x["records"]] for x in r["by_source"]["rows"]]),
        (
            "table",
            ["Destination", "Records"],
            [[x["dstaddr"], x["records"]] for x in r["by_destination"]["rows"]],
        ),
        (
            "table",
            ["Protocol", "Port", "Records"],
            [[x["protocol"], x["dstport"], x["records"]] for x in r["by_port"]["rows"]],
        ),
    ]


def _change(f: dict) -> list[Block]:
    c = f["change"]
    if c.get("status") != "available":
        return [("p", f"Not available: {c.get('why', c.get('status'))}")]
    t = c["by_path"]["totals"]
    out: list[Block] = [
        (
            "p",
            f"Previous window {c['previous_window'][0]} to {c['previous_window'][1]}. Counted traffic {_b(t['current'])} against {_b(t['previous'])} ({_b(t['delta'])}, {_pct(t['change_pct'])}).",
        ),
        (
            "table",
            ["Path", "Current", "Previous", "Change", "Status"],
            [
                [r["path_class"], _b(r["current"]), _b(r["previous"]), _b(r["delta"]), r["status"]]
                for r in c["by_path"]["rows"]
            ],
        ),
    ]
    new, gone = c["by_conversation"]["new"], c["by_conversation"]["gone"]
    if new:
        out += [
            ("h3", "New conversations"),
            (
                "table",
                ["Consumer", "Server", "Port", "Bytes"],
                [[r["consumer"], r["server"], r["port"], _b(r["current"])] for r in new],
            ),
        ]
    if gone:
        out += [
            ("h3", "Conversations that stopped"),
            (
                "table",
                ["Consumer", "Server", "Port", "Previous bytes"],
                [[r["consumer"], r["server"], r["port"], _b(r["previous"])] for r in gone],
            ),
        ]
    return out


def _recon(f: dict) -> list[Block]:
    r = f["reconciliation"]
    rows = []
    for x in r["rungs"]:
        if x["status"] == "used":
            rows.append([x["rung"], x["name"], "used", _ratio(x["ratio"]), x["explanation"]])
        else:
            rows.append([x["rung"], x["name"], "not used", "", x["why"]])
    out: list[Block] = [
        (
            "p",
            f"Verdict: {r['verdict']}. Tolerance ±{round(r['tolerance'] * 100, 2)}%. A ratio is flow-derived bytes divided by the comparison figure.",
        ),
        ("table", ["Rung", "Name", "Status", "Ratio", "Meaning"], rows),
    ]
    for x in r["rungs"]:
        if x["status"] == "used" and x["rung"] == 2:
            out.append(
                (
                    "table",
                    ["Gateway", "Flow bytes", "Metric bytes", "Ratio"],
                    [
                        [g, _b(v["flow_bytes"]), _b(v["metric_bytes"]), _ratio(v["ratio"])]
                        for g, v in x["per_gateway"].items()
                    ],
                )
            )
        if x["status"] == "used" and x["rung"] == 3:
            a = x["account_set"]
            out.append(
                (
                    "p",
                    f"Account set compared: {', '.join(a['compared'])}. Only in flow data: {', '.join(a['only_in_flow_data']) or 'none'}. Only in CUR: {', '.join(a['only_in_cur']) or 'none'}. {x['unit_note']}.",
                )
            )
            out.append(
                (
                    "table",
                    ["Category", "Flow bytes", "CUR bytes", "Ratio"],
                    [
                        [k, _b(v["flow_bytes"]), _b(v["cur_bytes"]), _ratio(v["ratio"])]
                        for k, v in x["by_category"].items()
                    ],
                )
            )
    out.append(("ul", r["known_differences"]))
    return out


def _options(f: dict) -> list[Block]:
    o = f["options"]
    out: list[Block] = [
        ("p", o["note"] + f" Rates: {o.get('rate_source')}, {o.get('region')}."),
        (
            "table",
            ["Path", "Volume", "Rate per GB (USD)", "Indicative cost (USD)"],
            [
                [x["item"], _b(x["bytes"]), _cell(x["rate_per_gb"]), _cell(x["indicative_cost"])]
                for x in o["lines"]
            ],
        ),
    ]
    if not o["options"]:
        return out + [("p", "No option is justified by flows in this window.")]
    for opt in o["options"]:
        rows = [
            ["Flows that justify it", _b(opt["justifying_flows_bytes"])],
            ["Current rate", f"{opt['current_rate']['name']} = {_cell(opt['current_rate']['per_gb'])}"],
            [
                "Alternative rate",
                f"{opt['alternative_rate']['name']} = {_cell(opt['alternative_rate']['per_gb'])}",
            ],
        ]
        if opt.get("processing_charge_difference") is not None:
            rows.append(["Processing charge difference (USD)", opt["processing_charge_difference"]])
        rows += [["Would change", opt["would_change"]], ["Would not change", opt["would_not_change"]]]
        if opt.get("volume_by_destination_bucket"):
            rows.append(
                [
                    "Volume by destination bucket",
                    ", ".join(f"{k}: {_b(v)}" for k, v in opt["volume_by_destination_bucket"].items()),
                ]
            )
        out += [("h3", opt["option"]), ("table", ["", ""], rows)]
    return out


def _tier(f: dict) -> list[Block]:
    t = f["tier"]
    out: list[Block] = [
        ("p", f"Tier: {t['tier']}. Provider: {t['provider']}."),
        (
            "table",
            ["Section", "Status", "Method"],
            [[k, v["status"], v["method"]] for k, v in t["sections"].items()],
        ),
    ]
    rec = t.get("upgrade_recommendation")
    if rec:
        out += [
            ("h3", "How to raise the tier"),
            ("p", "Enable this custom flow-log format the next time the flow log is created:"),
            ("code", rec["custom_format"]),
            ("p", rec["delivery_options"]),
        ]
        if rec.get("inventory_hint"):
            out.append(("p", "Inventory: " + rec["inventory_hint"]))
        out.append(("p", "Sections that gain confidence: " + ", ".join(rec["sections_that_gain_confidence"])))
    return out


def _method(f: dict) -> list[Block]:
    m = f["meta"]
    return [
        (
            "ul",
            [
                "One pass over the raw partitions builds an aggregate (day, hour, interface, addresses, normalised ports, action); every section reads the aggregate.",
                "Ports at or above 32768, and ports of 1024 and above that talk to a port below 1024, are stored as ephemeral (0). Conversations are paired by the one side with a service port; others are labelled ambiguous.",
                "Paths are classified by interface role, then route table, then the traffic-path field. Records on NAT, endpoint and transit interfaces re-observe workload traffic and are not added to volume totals.",
                "NAT traffic is measured on the NAT interfaces, translated (internet-side) leg only, and reconciled before any composition share is shown. Workloads are named from the untranslated (workload-side) leg.",
                "Destinations use the most specific match in ip-ranges.json (sync token "
                + str(f["destinations"]["ip_ranges_sync"])
                + "). Addresses matching only the generic EC2 or AMAZON ranges are AWS-hosted, unverified.",
                "All figures are computed by code in bytes and shown in decimal units. The model writes no numbers.",
                f"Resolver query-log naming: {f['destinations']['resolver']}.",
                f"Mode: {m['mode']}. Aggregate rows: {m['aggregate_rows']}.",
            ],
        )
    ]


def _repro(f: dict) -> list[Block]:
    rows = [
        [
            q["label"],
            q["execution_id"] or ("skipped: " + q["reason"] if q["skipped"] else ""),
            _b(q["scanned_bytes"]),
            _b(q["estimated_bytes"]) if q["estimated_bytes"] is not None else "",
        ]
        for q in f["queries"]
    ]
    out: list[Block] = [
        (
            "p",
            "Every figure comes from the aggregate loaded by the queries below. The statements are in data/aggregate_manifest.json.",
        ),
        ("table", ["Query", "Execution ID", "Scanned", "Estimated"], rows),
    ]
    n = f["nat"]
    if n.get("present"):
        ifs = ", ".join(f"'{i}'" for i in n["scope"]["nat_interfaces"])
        addrs = ", ".join(f"'{a}'" for a in n["scope"]["nat_addresses"])
        w0, w1 = f["meta"]["window"]
        out += [
            ("p", "Re-run the NAT translated-leg total against the aggregate:"),
            (
                "code",
                f"SELECT SUM(bytes) FROM {f['meta']['aggregate_table']}\nWHERE day BETWEEN '{w0}' AND '{w1}' AND action = 'ACCEPT'\n"  # nosec B608 - identifiers pass ident(); values are quoted or parsed  # nosemgrep: string-concat-in-list
                f"  AND interface_id IN ({ifs})\n  AND {translated_leg_sql(addrs, n['scope'].get('pkt_fields', True))}",
            ),
        ]
    return out


# ------------------------------------------------------------------------------ renderers


def _to_md(blocks: list[Block]) -> str:
    out: list[str] = []
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"{'#' * int(kind[1])} {b[1]}\n")
        elif kind == "p":
            out.append(f"{b[1]}\n")
        elif kind == "note":
            out.append(f"_{b[1]}_\n")
        elif kind == "caution":
            out += [f"> **Caution:** {c}\n" for c in b[1]]
        elif kind == "ul":
            out.append("\n".join(f"- {i}" for i in b[1]) + "\n")
        elif kind == "code":
            out.append(f"```\n{b[1]}\n```\n")
        elif kind == "svg":
            out.append("![Dependency diagram](diagram.svg)\n")
        elif kind == "table":
            head, rows = b[1], b[2]
            esc = lambda v: _cell(v).replace("|", "\\|").replace("\n", " ")  # noqa: E731
            out.append(
                "| " + " | ".join(esc(h) for h in head) + " |\n| " + " | ".join("---" for _ in head) + " |"
            )
            out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
            out.append("")
    return "\n".join(out)


_CSS = (
    "body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f23}"
    "table{border-collapse:collapse;margin:.5rem 0 1.2rem;font-size:.9rem}th,td{border:1px solid #d0d7de;padding:.3rem .6rem;text-align:left;vertical-align:top}"
    "th{background:#f3f4f6}.caution{background:#fff4ce;border-left:4px solid #d4a017;padding:.5rem .8rem;margin:.5rem 0}"
    "pre{background:#f6f8fa;padding:.8rem;overflow:auto}.note{color:#555;font-style:italic}"
)


def _to_html(blocks: list[Block], f: dict) -> str:
    e = html.escape
    out = [
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Network flow insight</title><style>{_CSS}</style></head><body>"
    ]
    for b in blocks:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{e(b[1])}</{kind}>")
        elif kind == "p":
            out.append(f"<p>{e(b[1])}</p>")
        elif kind == "note":
            out.append(f"<p class='note'>{e(b[1])}</p>")
        elif kind == "caution":
            out += [f"<div class='caution'><strong>Caution:</strong> {e(c)}</div>" for c in b[1]]
        elif kind == "ul":
            out.append("<ul>" + "".join(f"<li>{e(i)}</li>" for i in b[1]) + "</ul>")
        elif kind == "code":
            out.append(f"<pre>{e(b[1])}</pre>")
        elif kind == "svg":
            out.append(b[1])
        elif kind == "table":
            out.append(
                "<table><thead><tr>"
                + "".join(f"<th>{e(_cell(h))}</th>" for h in b[1])
                + "</tr></thead><tbody>"
                + "".join("<tr>" + "".join(f"<td>{e(_cell(c))}</td>" for c in r) + "</tr>" for r in b[2])
                + "</tbody></table>"
            )
    out.append("</body></html>")
    return "\n".join(out)


def _series_csv(f: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["day", "weekday", "bytes"])
    for s in f["time_profile"]["series"]:
        w.writerow([s["day"], s["weekday"], s["bytes"]])
    return buf.getvalue()


def _edges_csv(edges: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["consumer", "provider_bucket", "provider", "port", "bytes", "conversations", "paths"])
    for e in edges:
        w.writerow(
            [
                e["consumer"],
                e["provider_bucket"],
                e["provider"],
                e["port"],
                e["bytes"],
                e["conversations"],
                "|".join(e["paths"]),
            ]
        )
    return buf.getvalue()


def _manifest(f: dict) -> dict:
    return {
        "window": f["meta"]["window"],
        "raw_table": f["meta"]["raw_table"],
        "aggregate_table": f["meta"]["aggregate_table"],
        "aggregate_rows": f["meta"]["aggregate_rows"],
        "tier": f["meta"]["tier"],
        "inventory_provider": f["meta"]["inventory_provider"],
        "queries": f["queries"],
        "scan": f["meta"].get("scan", {}),
    }


def _diagram(edges: list[dict]) -> str:
    """Static SVG: consumers left, providers right, line weight by log(bytes). No scripts, no server."""
    top = edges[:40]
    consumers = sorted({e["consumer"] for e in top})
    providers = sorted({f"{e['provider_bucket']}:{e['provider']}" for e in top})
    row_h, left, right, width = 26, 200, 640, 900
    h = max(len(consumers), len(providers), 1) * row_h + 40
    cy = {c: 30 + i * row_h for i, c in enumerate(consumers)}
    py = {p: 30 + i * row_h for i, p in enumerate(providers)}
    biggest = max((e["bytes"] for e in top), default=1) or 1
    esc = html.escape
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {h}' width='{width}' height='{h}' font-family='sans-serif' font-size='11'>",
        "<title>Consumer to provider dependencies</title>",
    ]
    for e in top:
        key = f"{e['provider_bucket']}:{e['provider']}"
        sw = 0.5 + 5 * math.log10(1 + e["bytes"]) / math.log10(1 + biggest)
        parts.append(
            f"<line x1='{left}' y1='{cy[e['consumer']]}' x2='{right}' y2='{py[key]}' stroke='#4a6fa5' stroke-opacity='0.55' stroke-width='{sw:.2f}'>"
            f"<title>{esc(e['consumer'])} to {esc(key)}:{e['port']} {fmt_bytes(e['bytes'])}</title></line>"
        )
    for c, y in cy.items():
        parts.append(
            f"<text x='{left - 6}' y='{y + 4}' text-anchor='end'>{esc(c)}</text><circle cx='{left}' cy='{y}' r='3' fill='#4a6fa5'/>"
        )
    for p, y in py.items():
        parts.append(
            f"<circle cx='{right}' cy='{y}' r='3' fill='#a5574a'/><text x='{right + 6}' y='{y + 4}'>{esc(p)}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)
