# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: CloudWatch bytes for NAT gateways, interface endpoints and TGW attachments.

One ``GetMetricData`` call per Region in the account the agent runs in. Metrics exist only in the account
that owns the gateway, so source accounts appear only if this account is already a CloudWatch monitoring
account. The tool never assumes into other accounts. Each result carries ``comparable_bytes``: the sum that
corresponds to the flow-derived translated or processed bytes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

NAT_METRICS = ("BytesOutToDestination", "BytesInFromDestination", "BytesInFromSource", "BytesOutToSource")


def _window(first_day: str, last_day: str) -> tuple[datetime, datetime]:
    a = datetime.fromisoformat(first_day).replace(tzinfo=UTC)
    b = datetime.fromisoformat(last_day).replace(tzinfo=UTC) + timedelta(days=1)
    return a, b


def get_gateway_metrics(
    cloudwatch: Any, gateways: list[dict], first_day: str, last_day: str
) -> dict[str, dict] | str:
    """``gateways``: ``[{"kind": "nat"|"endpoint"|"tgw", "id": "..."}]``. Returns ``{id: {...}}`` or a reason."""
    if not gateways:
        return "no gateways to query"
    start, end = _window(first_day, last_day)
    queries: list[dict] = []
    meta: dict[str, tuple[str, str, str]] = {}
    for i, g in enumerate(gateways):
        if g["kind"] == "nat":
            for j, m in enumerate(NAT_METRICS):
                qid = f"q{i}_{j}"
                queries.append(_q(qid, "AWS/NATGateway", m, [("NatGatewayId", g["id"])]))
                meta[qid] = (g["id"], "nat", m)
        elif g["kind"] == "tgw":
            for j, m in enumerate(("BytesIn", "BytesOut")):
                qid = f"q{i}_{j}"
                queries.append(_q(qid, "AWS/TransitGateway", m, [("TransitGatewayAttachment", g["id"])]))
                meta[qid] = (g["id"], "tgw", m)
        elif g["kind"] == "endpoint":
            dims = _endpoint_dimensions(cloudwatch, g["id"])
            if dims:
                qid = f"q{i}_0"
                queries.append(_q(qid, "AWS/PrivateLinkEndpoints", "BytesProcessed", dims))
                meta[qid] = (g["id"], "endpoint", "BytesProcessed")
    if not queries:
        return "no metric dimensions found for the requested gateways"
    sums: dict[str, int] = {}
    try:
        for k in range(0, len(queries), 400):
            token = None
            while True:
                kw: dict[str, Any] = {
                    "MetricDataQueries": queries[k : k + 400],
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampAscending",
                }
                if token:
                    kw["NextToken"] = token
                page = cloudwatch.get_metric_data(**kw)
                for r in page.get("MetricDataResults", []):
                    sums[r["Id"]] = sums.get(r["Id"], 0) + int(sum(r.get("Values", [])))
                token = page.get("NextToken")
                if not token:
                    break
    except Exception as exc:
        return f"CloudWatch query failed: {type(exc).__name__}: {str(exc)[:160]}"
    out: dict[str, dict] = {}
    for qid, (gid, kind, metric) in meta.items():
        e = out.setdefault(gid, {"kind": kind, "metrics": {}})
        e["metrics"][metric] = sums.get(qid, 0)
    for gid, e in list(out.items()):
        m = e["metrics"]
        if not any(m.values()):
            del out[gid]  # no datapoints: the metric exists in another account or the gateway was idle
            continue
        if e["kind"] == "nat":
            e["comparable_bytes"] = m.get("BytesOutToDestination", 0) + m.get("BytesInFromDestination", 0)
        elif e["kind"] == "endpoint":
            e["comparable_bytes"] = m.get("BytesProcessed", 0)
        else:
            e["comparable_bytes"] = m.get("BytesIn", 0) + m.get("BytesOut", 0)
    return (
        out or "no datapoints returned; the gateways' metrics live in another account or the window is idle"
    )


def _q(qid: str, ns: str, metric: str, dims: list[tuple[str, str]]) -> dict:
    return {
        "Id": qid,
        "ReturnData": True,
        "MetricStat": {
            "Metric": {
                "Namespace": ns,
                "MetricName": metric,
                "Dimensions": [{"Name": n, "Value": v} for n, v in dims],
            },
            "Period": 86400,
            "Stat": "Sum",
        },
    }


def _endpoint_dimensions(cw: Any, endpoint_id: str) -> list[tuple[str, str]] | None:
    try:
        res = cw.list_metrics(
            Namespace="AWS/PrivateLinkEndpoints",
            MetricName="BytesProcessed",
            Dimensions=[{"Name": "VPC Endpoint Id", "Value": endpoint_id}],
        )
    except Exception:
        return None
    for m in res.get("Metrics", []):
        return [(d["Name"], d["Value"]) for d in m["Dimensions"]]
    return None
