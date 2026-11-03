# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 5 — route / prefix counts approaching a limit (design.md D§4.5).

The finding identity never contains the count, so a crossing stays KNOWN while the
count climbs. The on-prem -> AWS finding always says "Approximate" (requirements §5).
"""

from __future__ import annotations

from collections import defaultdict

from drift_core.checks import EvaluationContext
from drift_core.finding import Finding, canonical_prefix
from drift_core.limits import (
    CLOUDWAN_TO_ONPREM_PER_DXGW,
    CLOUDWAN_TOTAL_ROUTES,
    ONPREM_TO_AWS_PER_VIF,
    TGW_TO_ONPREM_PER_ASSOCIATION,
    TGW_TOTAL_ROUTES,
    Limit,
    percent,
    threshold_for,
)
from drift_core.snapshot import ip_family


def _finding(ctx: EvaluationContext, limit: Limit, region: str, identity: tuple[str, ...], count: int,
             limit_value: int, message: str, context: dict, assumed_default: bool = False) -> Finding | None:
    threshold = threshold_for(limit, ctx.limit_threshold_percent, ctx.limit_threshold_overrides)
    pct = percent(count, limit_value)
    if pct < threshold:
        return None
    return Finding(
        check="check5", kind="limit-threshold", severity="drift", region=region,
        identity=(limit.name, *identity),
        expected={"below_percent": threshold},
        observed={"count": count, "limit": limit_value, "percent": pct},
        context={**context, "limit_name": limit.name, "limit_description": limit.description,
                 "doc_url": limit.doc_url, "approximate": limit.approximate,
                 "limit_basis": "assumed-default" if assumed_default else limit.limit_source},
        message=message)


def _dx_attachment_prefixes(ctx: EvaluationContext) -> dict[str, dict[str, set[str]]]:
    """dxgw_id -> family -> installed prefixes learned from on-prem via that DX gateway."""
    learned: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for snap in ctx.regions.values():
        for table in snap.get("route_tables") or []:
            for route in table.get("routes") or []:
                if (route.get("type") or "").lower() != "propagated":
                    continue
                for att in route.get("attachments") or []:
                    if (att.get("resource_type") or "").lower() == "direct-connect-gateway":
                        prefix = canonical_prefix(route["prefix"])
                        learned[att["resource_id"]][ip_family(prefix)].add(prefix)
    if ctx.cloudwan:
        for table in ctx.cloudwan.get("route_tables") or []:
            for route in table.get("routes") or []:
                for dest in route.get("destinations") or []:
                    if (dest.get("resource_type") or "").lower() in ("direct-connect-gateway", "dxgw") and dest.get(
                            "resource_id"):
                        prefix = canonical_prefix(route["prefix"])
                        learned[dest["resource_id"]][ip_family(prefix)].add(prefix)
    return learned


def _onprem_to_aws(ctx: EvaluationContext) -> list[Finding]:
    learned = _dx_attachment_prefixes(ctx)
    findings: list[Finding] = []
    for region, snap in sorted(ctx.regions.items()):
        for vif in snap.get("dx_virtual_interfaces") or []:
            if (vif.get("type") or "").lower() != "transit" or not vif.get("dxgw_id"):
                continue
            for family in ("ipv4", "ipv6"):
                count = len(learned.get(vif["dxgw_id"], {}).get(family, set()))
                if count == 0:
                    continue
                allocation = (vif.get("prefix_allocation") or {}).get(family)
                assumed = allocation is None
                limit_value = ONPREM_TO_AWS_PER_VIF.default_limit if assumed else int(allocation)
                pct = percent(count, limit_value)
                message = (f"Approximate: {count} installed routes of {limit_value} allocated ({pct} %) on "
                           f"{vif['vif_id']} {family}; received count may be higher than installed.")
                if assumed:
                    message += " Allocation not reported by the API; documented default of 100 assumed."
                f = _finding(ctx, ONPREM_TO_AWS_PER_VIF, region, (vif["vif_id"], family), count, limit_value,
                             message, {"vif_id": vif["vif_id"], "dxgw_id": vif["dxgw_id"], "address_family": family},
                             assumed_default=assumed)
                if f:
                    findings.append(f)
    return findings


def _tgw_to_onprem(ctx: EvaluationContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for region, snap in sorted(ctx.regions.items()):
        for assoc in snap.get("dx_gateway_associations") or []:
            if (assoc.get("associated_gateway_type") or "").lower() != "transitgateway":
                continue
            if assoc["association_id"] in seen:
                continue
            seen.add(assoc["association_id"])
            count = len(set(assoc.get("allowed_prefixes") or []))
            limit_value = TGW_TO_ONPREM_PER_ASSOCIATION.default_limit
            f = _finding(ctx, TGW_TO_ONPREM_PER_ASSOCIATION, region, (assoc["association_id"],), count, limit_value,
                         (f"{count} of {limit_value} allowed prefixes ({percent(count, limit_value)} %) on DX gateway "
                          f"{assoc['dxgw_id']} association with {assoc['associated_gateway_id']}."),
                         {"dxgw_id": assoc["dxgw_id"], "associated_gateway_id": assoc["associated_gateway_id"]})
            if f:
                findings.append(f)
    return findings


def _cloudwan_to_onprem(ctx: EvaluationContext) -> list[Finding]:
    cw = ctx.cloudwan
    if not cw:
        return []
    dx_segments: dict[str, set[str]] = defaultdict(set)  # dxgw attachment id -> segments
    for att in cw.get("attachments") or []:
        if att.get("attachment_type") == "DIRECT_CONNECT_GATEWAY" and att.get("segment_name"):
            dx_segments[att["attachment_id"]].add(att["segment_name"].lower())
    findings: list[Finding] = []
    for att_id, segments in sorted(dx_segments.items()):
        prefixes: set[str] = set()
        for table in cw.get("route_tables") or []:
            if str(table.get("segment", "")).lower() not in segments:
                continue
            for route in table.get("routes") or []:
                if (route.get("state") or "").upper() != "ACTIVE":
                    continue
                if any(d.get("attachment_id") == att_id for d in route.get("destinations") or []):
                    continue  # learned from on-prem via this attachment, not advertised to it
                prefixes.add(canonical_prefix(route["prefix"]))
        count = len(prefixes)
        limit_value = CLOUDWAN_TO_ONPREM_PER_DXGW.default_limit
        f = _finding(ctx, CLOUDWAN_TO_ONPREM_PER_DXGW, "global", (att_id,), count, limit_value,
                     (f"Upper bound: {count} of {limit_value} prefixes ({percent(count, limit_value)} %) installed in "
                      f"the segment(s) of DX gateway attachment {att_id}, each a candidate for advertisement "
                      "to on-premises."),
                     {"attachment_id": att_id, "segments": sorted(segments),
                      "core_network_id": cw.get("core_network_id", "")})
        if f:
            findings.append(f)
    return findings


def _tgw_totals(ctx: EvaluationContext) -> list[Finding]:
    findings: list[Finding] = []
    for region, snap in sorted(ctx.regions.items()):
        totals: dict[str, int] = defaultdict(int)
        for table in snap.get("route_tables") or []:
            totals[table.get("tgw_id", "")] += len(table.get("routes") or [])
        for tgw_id, count in sorted(totals.items()):
            limit_value = TGW_TOTAL_ROUTES.default_limit
            f = _finding(ctx, TGW_TOTAL_ROUTES, region, (tgw_id,), count, limit_value,
                         (f"{count} of {limit_value} routes ({percent(count, limit_value)} %) across all route "
                          f"tables of transit gateway {tgw_id}."), {"tgw_id": tgw_id})
            if f:
                findings.append(f)
    return findings


def _cloudwan_totals(ctx: EvaluationContext) -> list[Finding]:
    cw = ctx.cloudwan
    if not cw:
        return []
    count = sum(len(t.get("routes") or []) for t in cw.get("route_tables") or [])
    limit_value = CLOUDWAN_TOTAL_ROUTES.default_limit
    core_id = cw.get("core_network_id", "")
    f = _finding(ctx, CLOUDWAN_TOTAL_ROUTES, "global", (core_id,), count, limit_value,
                 (f"{count} of {limit_value} installed routes ({percent(count, limit_value)} %) across all "
                  f"segments of core network {core_id}."), {"core_network_id": core_id})
    return [f] if f else []


def run(ctx: EvaluationContext) -> list[Finding]:
    return (_onprem_to_aws(ctx) + _tgw_to_onprem(ctx) + _cloudwan_to_onprem(ctx)
            + _tgw_totals(ctx) + _cloudwan_totals(ctx))
