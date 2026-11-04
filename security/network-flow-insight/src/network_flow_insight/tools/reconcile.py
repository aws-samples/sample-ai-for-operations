# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: the reconciliation ladder.

Rung 1: in-data leg check (always). Rung 2: gateway CloudWatch metrics. Rung 3: Cost and Usage Report.
Rung 4: a reference figure the operator types in. Each rung is used when available; the result names
the rungs used and the rungs unavailable, with the reason.
"""

from __future__ import annotations

KNOWN_DIFFERENCES = (
    "Flow-log bytes include IP headers; billed and payload-based figures differ by protocol framing.",
    "Flow records are aggregated over the capture window (1 or 10 minutes), so day boundaries blur slightly.",
    "Unsolicited inbound to a NAT address (internet scans) is accepted on the internet side but never translated; "
    "it is reported apart and kept out of the translated leg, as the gateway's own metrics keep it out.",
    "A flow that spans a capture-window boundary can be logged on the two NAT legs in different windows, so short "
    "windows show a small difference between the legs.",
)

DIAGNOSES = {
    "ok": "within tolerance",
    "both-legs-counted": "ratio near 2: both legs are still included in the flow-derived figure",
    "above": (
        "ratio well above 1: non-NAT traffic has leaked into the filter, addresses are double-listed, or (leg check)"
        " internet-side traffic reached the NAT address without a workload leg"
    ),
    "below": (
        "ratio well below 1: coverage is incomplete (missing NAT address, interface, account or day; on the leg"
        " check, records on a NAT interface with no known NAT address)"
    ),
    "no-data": "no comparison figure",
}


def diagnose_ratio(ratio: float | None, tolerance: float, *, both_legs_possible: bool = True) -> str:
    """Name what a flow-derived / reference ratio means.

    ``both_legs_possible=False`` for the in-data leg check, which compares the legs with each other and so
    cannot count both legs; a ratio near 2 there is just "above".
    """
    if ratio is None:
        return "no-data"
    if abs(ratio - 1) <= tolerance:
        return "ok"
    if both_legs_possible and 1.8 <= ratio <= 2.2:
        return "both-legs-counted"
    return "above" if ratio > 1 else "below"


def _ratio(num: float, den: float) -> float | None:
    return round(num / den, 6) if den else None


def _rung(rung: int, name: str, tolerance: float, **kw) -> dict:
    ratio = kw.get("ratio")
    d = diagnose_ratio(ratio, tolerance, both_legs_possible=kw.pop("both_legs_possible", True))
    return {
        "rung": rung,
        "name": name,
        "status": "used",
        "ratio": ratio,
        "diagnosis": d,
        "explanation": DIAGNOSES[d],
        "ok": d == "ok",
        **{k: v for k, v in kw.items() if k != "ratio"},
    }


def _unavailable(rung: int, name: str, why: str) -> dict:
    return {"rung": rung, "name": name, "status": "unavailable", "why": why}


def reconcile(
    *,
    leg_check: dict | None,
    flow_by_gateway: dict[str, int] | None = None,
    metrics: dict | str | None = None,
    flow_by_category: dict[str, dict[str, int]] | None = None,
    flow_accounts: list[str] | None = None,
    cur: list[dict] | str | None = None,
    reference: dict | None = None,
    flow_for_reference: dict[str, int] | None = None,
    tolerance: float = 0.05,
    bytes_per_billed_gb: int = 10**9,
    skipdata_by_gateway: dict[str, int] | None = None,
) -> dict:
    """Combine every rung that has inputs.

    ``leg_check``: output of ``nat_leg_check``. ``flow_by_gateway``: translated bytes per gateway id.
    ``metrics``: ``{gateway_id: {kind, metrics, comparable_bytes}}`` (from ``get_gateway_metrics``) or a string
    explaining why it is unavailable. ``flow_by_category``: ``{category: {account_id: bytes}}`` with
    categories ``nat_processing`` and ``internet_out`` and ``regional``. ``cur``: rows ``{account_id,
    usage_type, usage_gb}``. ``reference``: ``{category, bytes, scope, window}``.
    """
    rungs: list[dict] = []

    if leg_check and leg_check.get("overall", {}).get("ratio") is not None:
        o = leg_check["overall"]
        rungs.append(
            _rung(
                1,
                "in-data leg check",
                tolerance,
                ratio=o["ratio"],
                translated_bytes=o["translated_bytes"],
                untranslated_bytes=o["untranslated_bytes"],
                unmatched_bytes=o.get("unmatched_bytes", 0),
                both_legs_possible=False,
                per_interface={k: v["ratio"] for k, v in leg_check.get("by_interface", {}).items()},
            )
        )
    else:
        rungs.append(_unavailable(1, "in-data leg check", "no NAT interface rows in the aggregate"))

    if isinstance(metrics, dict) and metrics and flow_by_gateway:
        per: dict[str, dict] = {}
        flow_sum = met_sum = 0
        for gw, flow in sorted(flow_by_gateway.items()):
            m = metrics.get(gw)
            if not isinstance(m, dict):
                continue
            expected = int(m["comparable_bytes"])
            per[gw] = {"flow_bytes": flow, "metric_bytes": expected, "ratio": _ratio(flow, expected)}
            per[gw]["diagnosis"] = diagnose_ratio(per[gw]["ratio"], tolerance)
            skipped = (skipdata_by_gateway or {}).get(gw, 0)
            if skipped:
                per[gw]["skipdata_records"] = skipped
            flow_sum += flow
            met_sum += expected
        if per:
            r2 = _rung(
                2,
                "gateway metrics",
                tolerance,
                ratio=_ratio(flow_sum, met_sum),
                per_gateway=per,
                flow_bytes=flow_sum,
                metric_bytes=met_sum,
            )
            skipped_total = sum(p.get("skipdata_records", 0) for p in per.values())
            if skipped_total and r2["diagnosis"] == "below":
                # SKIPDATA records say the capture dropped records on these interfaces; the amount is unknown, and
                # it shows up as exactly this kind of shortfall against the gateway's own counters.
                r2["explanation"] += (
                    f"; the gateways' interfaces logged {skipped_total} SKIPDATA record(s) in the window, so flow logs"
                    " dropped records there by an unknown amount: the likely cause of the shortfall"
                )
            rungs.append(r2)
        else:
            rungs.append(
                _unavailable(
                    2, "gateway metrics", "metrics returned nothing for the gateways in the flow data"
                )
            )
    else:
        why = metrics if isinstance(metrics, str) else "no gateway metrics reachable from this account"
        rungs.append(_unavailable(2, "gateway metrics", why))

    if isinstance(cur, list) and cur and flow_by_category:
        rungs.append(_cur_rung(cur, flow_by_category, flow_accounts or [], tolerance, bytes_per_billed_gb))
    else:
        why = cur if isinstance(cur, str) else "no Cost and Usage Report access configured"
        rungs.append(_unavailable(3, "Cost and Usage Report", why))

    if reference and flow_for_reference and reference.get("category") in flow_for_reference:
        flow = flow_for_reference[reference["category"]]
        rungs.append(
            _rung(
                4,
                "operator reference figure",
                tolerance,
                ratio=_ratio(flow, reference["bytes"]),
                flow_bytes=flow,
                reference_bytes=reference["bytes"],
                scope=reference.get("scope"),
                window=reference.get("window"),
            )
        )
    else:
        rungs.append(_unavailable(4, "operator reference figure", "no reference figure supplied"))

    used = [r for r in rungs if r["status"] == "used"]
    ok = [r for r in used if r["ok"]]
    failing = [r for r in used if not r["ok"]]
    if not used:
        verdict = "unverified"
    elif ok and not failing:
        verdict = "reconciled"
    elif ok:
        verdict = "partially-reconciled"
    else:
        verdict = "not-reconciled"
    caution = None
    if failing:
        caution = "; ".join(
            f"rung {r['rung']} ({r['name']}): ratio {r['ratio']}, {r['explanation']}" for r in failing
        )
    return {
        "verdict": verdict,
        "show_shares": bool(ok),
        "shares_caution": None
        if (ok and not failing)
        else (caution or "no rung could confirm the NAT totals"),
        "rungs": rungs,
        "rungs_used": [r["rung"] for r in used],
        "rungs_unavailable": [
            {"rung": r["rung"], "name": r["name"], "why": r["why"]}
            for r in rungs
            if r["status"] == "unavailable"
        ],
        "tolerance": tolerance,
        "known_differences": list(KNOWN_DIFFERENCES),
    }


_USAGE_CATEGORY = {
    "NatGateway-Bytes": "nat_processing",
    "DataTransfer-Out-Bytes": "internet_out",
    "DataTransfer-Regional-Bytes": "regional",
}


def _cur_rung(
    cur: list[dict],
    flow_by_category: dict[str, dict[str, int]],
    flow_accounts: list[str],
    tolerance: float,
    bytes_per_gb: int,
) -> dict:
    cur_accounts = sorted({r["account_id"] for r in cur})
    flow_accts = sorted(set(flow_accounts) or {a for v in flow_by_category.values() for a in v})
    common = sorted(set(cur_accounts) & set(flow_accts))
    only_flow = sorted(set(flow_accts) - set(cur_accounts))
    only_cur = sorted(set(cur_accounts) - set(flow_accts))
    cats: dict[str, dict] = {}
    flow_sum = cur_sum = 0
    for row in cur:
        if row["account_id"] not in common:
            continue
        for suffix, cat in _USAGE_CATEGORY.items():
            if row["usage_type"].endswith(suffix):
                c = cats.setdefault(cat, {"cur_bytes": 0, "flow_bytes": 0})
                c["cur_bytes"] += int(round(row["usage_gb"] * bytes_per_gb))
    for cat, c in cats.items():
        c["flow_bytes"] = sum(v for a, v in flow_by_category.get(cat, {}).items() if a in common)
        c["ratio"] = _ratio(c["flow_bytes"], c["cur_bytes"])
        c["diagnosis"] = diagnose_ratio(c["ratio"], tolerance)
        flow_sum += c["flow_bytes"]
        cur_sum += c["cur_bytes"]
    mismatch = bool(only_flow or only_cur)
    r = _rung(
        3,
        "Cost and Usage Report",
        tolerance,
        ratio=_ratio(flow_sum, cur_sum),
        by_category=cats,
        account_set={"compared": common, "only_in_flow_data": only_flow, "only_in_cur": only_cur},
        unit_note=f"billed GB taken as {bytes_per_gb} bytes; confirm against the CUR's unit",
    )
    if mismatch:
        r["account_set_mismatch"] = True
        r["explanation"] += (
            f"; account sets differ (only in flow data: {only_flow or 'none'}; only in CUR: {only_cur or 'none'})"
        )
    return r
