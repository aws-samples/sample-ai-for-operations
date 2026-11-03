# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 3 — blackhole routes (design.md D§4.3). Always drift; needs no intent."""

from __future__ import annotations

from drift_core.checks import EvaluationContext
from drift_core.finding import Finding, canonical_prefix


def run(ctx: EvaluationContext) -> list[Finding]:
    findings: list[Finding] = []
    cw = ctx.cloudwan
    if cw:
        core_id = cw.get("core_network_id", "")
        for table in cw.get("route_tables") or []:
            segment, edge = table.get("segment", ""), table.get("edge", "")
            for route in table.get("routes") or []:
                if (route.get("state") or "").upper() != "BLACKHOLE":
                    continue
                prefix = canonical_prefix(route.get("prefix", ""))
                findings.append(Finding(
                    check="check3", kind="blackhole-route", severity="drift", region=edge or "global",
                    identity=(f"{core_id}/{segment}/{edge}".lower(), prefix),
                    observed={"state": "BLACKHOLE", "type": route.get("type")},
                    context={"platform": "cloudwan", "core_network_id": core_id, "segment": segment,
                             "edge": edge, "prefix": prefix},
                    message=f"Blackhole route {prefix} in Cloud WAN segment '{segment}' at {edge}."))
    for region, snap in sorted(ctx.regions.items()):
        for table in snap.get("route_tables") or []:
            rtb_id = table["route_table_id"]
            for route in table.get("routes") or []:
                if (route.get("state") or "").lower() != "blackhole":
                    continue
                prefix = canonical_prefix(route.get("prefix", ""))
                findings.append(Finding(
                    check="check3", kind="blackhole-route", severity="drift", region=region,
                    identity=(rtb_id, prefix),
                    observed={"state": "blackhole", "type": route.get("type")},
                    context={"platform": "tgw", "tgw_id": table.get("tgw_id"), "route_table_id": rtb_id,
                             "prefix": prefix, "tags": table.get("tags") or {}},
                    message=f"Blackhole route {prefix} ({route.get('type')}) in TGW route table {rtb_id}."))
    return findings
