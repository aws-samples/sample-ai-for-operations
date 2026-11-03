# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 6 — hybrid path intent (tasks.md 2.4, design.md D§4.6).

For each `hybrid_paths` entry, find the installed routes for the prefix (exact match, after
normalization) in every TGW route table and Cloud WAN segment/edge table.

- prefix-not-found:   no table has the prefix.
- wrong-exit-region:  a table's route has a next hop whose exit Region is known and differs from
                      `exit_region`. Cloud WAN: the destination's edge. TGW: the table's Region, except
                      a peering next hop, whose exit is another Region and is not judged.
- not-preferred:      in the preferred resource's Region (or everywhere, for a DX gateway), a table
                      that has the prefix but not via `preferred`. A preferred VIF matches the DX gateway
                      it is attached to.
- backup:             in the installed set anywhere -> fine. Otherwise judged at attachment level
                      (verified in task 0.3): healthy -> backup-unverifiable (informational);
                      missing or unhealthy -> backup-absent (drift).
Anything "not found" while collection was incomplete becomes a `system` finding, never drift.
"""

from __future__ import annotations

from typing import Any

from drift_core.checks import EvaluationContext
from drift_core.checks.resources import lookup, vifs
from drift_core.finding import Finding, canonical_prefix


def _entries(ctx: EvaluationContext, prefix: str) -> list[dict[str, Any]]:
    entries = []
    for region, snap in sorted(ctx.regions.items()):
        for table in snap.get("route_tables") or []:
            for route in table.get("routes") or []:
                if route.get("state") == "active" and canonical_prefix(route.get("prefix", "")) == prefix:
                    entries.append({"platform": "tgw", "region": region, "table": table["route_table_id"],
                                    "dests": [{**d, "exit": None if d.get("resource_type") == "peering" else region}
                                              for d in route.get("attachments") or []]})
    if ctx.cloudwan:
        core = ctx.cloudwan.get("core_network_id", "")
        for table in ctx.cloudwan.get("route_tables") or []:
            for route in table.get("routes") or []:
                if route.get("state") == "ACTIVE" and canonical_prefix(route.get("prefix", "")) == prefix:
                    entries.append({"platform": "cloudwan", "region": table.get("edge", ""),
                                    "table": f"{core}/{table.get('segment')}/{table.get('edge')}".lower(),
                                    "core_network_id": core,
                                    "dests": [{**d, "exit": d.get("edge")} for d in route.get("destinations") or []]})
    return entries


def _matches(value: str, dest: dict[str, Any], vif_dxgw: dict[str, str]) -> bool:
    ids = {str(dest.get("attachment_id") or "").lower(), str(dest.get("resource_id") or "").lower()}
    v = value.lower()
    return v in ids or (vif_dxgw.get(v, "") in ids and v in vif_dxgw)


def _finding(kind: str, severity: str, entry: dict[str, Any] | None, prefix: str, identity: tuple[str, ...],
             message: str, **extra: Any) -> Finding:
    context = {"prefix": prefix, **extra.pop("context", {})}
    region = "global"
    if entry is not None:
        region = entry["region"] or "global"
        context.update({"platform": entry["platform"], "table": entry["table"]})
        if entry.get("core_network_id"):
            context["core_network_id"] = entry["core_network_id"]
    check = "check6" if severity != "system" else "system"
    return Finding(check=check, kind=kind, severity=severity, region=region, identity=(prefix, *identity),
                   context=context, message=message, **extra)


def run(ctx: EvaluationContext) -> list[Finding]:
    paths = (ctx.intent or {}).get("hybrid_paths") or []
    if not paths:
        return []
    vif_dxgw = {vid: (v.get("dxgw_id") or "").lower() for vid, (_, v) in vifs(ctx).items() if v.get("dxgw_id")}
    findings: list[Finding] = []
    for path in paths:
        prefix = path["prefix"]
        entries = _entries(ctx, prefix)
        if not entries:
            if ctx.regions_not_evaluated:
                findings.append(_finding("hybrid-path-unverified", "system", None, prefix, ("not-found",),
                                         f"Hybrid path {prefix}: not installed in any evaluated table, but some "
                                         "Regions were not evaluated."))
            else:
                findings.append(_finding("hybrid-path-prefix-not-found", "drift", None, prefix, (),
                                         f"Hybrid path {prefix}: the prefix is not installed in any route table.",
                                         expected={"installed": True}, observed={"installed": False}))
            continue

        exit_region = path.get("exit_region")
        if exit_region:
            for e in entries:
                wrong = sorted({d["exit"] for d in e["dests"] if d.get("exit") and d["exit"] != exit_region})
                if wrong:
                    findings.append(_finding(
                        "hybrid-path-wrong-exit-region", "drift", e, prefix, (e["table"],),
                        f"Hybrid path {prefix}: {e['table']} sends it out via {', '.join(wrong)}, "
                        f"not {exit_region}.", expected={"exit_region": exit_region}, observed={"exit": wrong}))

        preferred = path.get("preferred")
        if preferred:
            state = lookup(preferred, ctx)
            scope = [e for e in entries if state.region is None or e["region"] == state.region]
            for e in scope:
                if not any(_matches(preferred, d, vif_dxgw) for d in e["dests"]):
                    via = sorted({str(d.get("attachment_id") or d.get("resource_id")) for d in e["dests"]})
                    findings.append(_finding(
                        "hybrid-path-not-preferred", "drift", e, prefix, (e["table"],),
                        f"Hybrid path {prefix}: {e['table']} routes it via {', '.join(via)}, not the preferred "
                        f"{preferred} ({state.detail}).", expected={"preferred": preferred}, observed={"via": via}))

        backup = path.get("backup")
        if backup and not any(_matches(backup, d, vif_dxgw) for e in entries for d in e["dests"]):
            state = lookup(backup, ctx)
            context = {"context": {"backup": backup, "detail": state.detail}}
            if state.unverifiable:
                findings.append(_finding("hybrid-path-unverified", "system", None, prefix, ("backup", backup),
                                         f"Hybrid path {prefix}: backup {backup} not found, but its collection was "
                                         "incomplete this run.", **context))
            elif state.found and state.healthy:
                findings.append(_finding(
                    "hybrid-path-backup-unverifiable", "informational", None, prefix, ("backup", backup),
                    f"Hybrid path {prefix}: backup {backup} is healthy ({state.detail}); whether it advertises "
                    f"{prefix} cannot be verified from the control-plane APIs.", **context))
            else:
                findings.append(_finding(
                    "hybrid-path-backup-absent", "drift", None, prefix, ("backup", backup),
                    f"Hybrid path {prefix}: backup {backup} is not available ({state.detail}).",
                    expected={"backup": "healthy"}, observed={"backup": state.detail}, **context))
    return findings
