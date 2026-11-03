# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 2 — prefix leak between routing domains (design.md D§4.2).

Phase 1: Cloud WAN (intent = core network policy). TGW (intent = isolation matrix in the
intent file) is Phase 2 (tasks.md 2.2) and returns nothing until then.

Identity per finding: (route table, prefix, source attachment) — never the whole leak set.
"""

from __future__ import annotations

from drift_core.checks import EvaluationContext
from drift_core.checks.cloudwan_policy import isolated_segments, shared_pairs, static_routes
from drift_core.finding import Finding, canonical_prefix


def _isolation_leak(core_id: str, table_ref: str, segment: str, edge: str, prefix: str, dest: dict) -> Finding:
    source = dest.get("attachment_id") or dest.get("resource_id") or segment
    return Finding(
        check="check2", kind="cloudwan-isolation-leak", severity="drift", region=edge or "global",
        identity=(table_ref, prefix, source),
        expected={"isolate_attachments": True}, observed={"source_attachment": source},
        context={"core_network_id": core_id, "segment": segment, "edge": edge, "prefix": prefix,
                 "source_attachment": dest.get("attachment_id"), "source_resource_type": dest.get("resource_type")},
        message=(f"Segment '{segment}' has isolate-attachments set, but its route table at {edge} has a "
                 f"propagated route {prefix} to VPC attachment {source} in the same segment."))


def check_cloudwan(ctx: EvaluationContext) -> list[Finding]:
    cw = ctx.cloudwan
    if not cw:
        return []
    policy = cw.get("policy") or {}
    pairs = shared_pairs(policy)
    statics = static_routes(policy)
    isolated = isolated_segments(policy)
    core_id = cw.get("core_network_id", "")
    findings: list[Finding] = []
    for table in cw.get("route_tables") or []:
        segment = str(table.get("segment", "")).lower()
        edge = table.get("edge", "")
        table_ref = f"{core_id}/{segment}/{edge}"
        for route in table.get("routes") or []:
            if (route.get("state") or "").upper() == "BLACKHOLE":
                continue  # check 3 owns blackholes
            prefix = canonical_prefix(route.get("prefix", ""))
            for dest in route.get("destinations") or []:
                source_segment = (dest.get("segment") or "").lower()
                if not source_segment:
                    continue
                if source_segment == segment:
                    if segment in isolated and (dest.get("resource_type") or "").lower() == "vpc" \
                            and (route.get("type") or "").upper() == "PROPAGATED":
                        findings.append(_isolation_leak(core_id, table_ref, segment, edge, prefix, dest))
                    continue
                if frozenset((segment, source_segment)) in pairs:
                    continue
                if (route.get("type") or "").upper() == "STATIC" and (segment, prefix) in statics:
                    continue
                source = dest.get("attachment_id") or dest.get("resource_id") or source_segment
                findings.append(Finding(
                    check="check2", kind="cloudwan-prefix-leak", severity="drift", region=edge or "global",
                    identity=(table_ref, prefix, source),
                    expected={"visible_segments": sorted(
                        {segment} | {s for p in pairs if segment in p for s in p})},
                    observed={"source_segment": source_segment, "route_type": route.get("type")},
                    context={"core_network_id": core_id, "segment": segment, "edge": edge, "prefix": prefix,
                             "source_attachment": dest.get("attachment_id"),
                             "source_resource_type": dest.get("resource_type")},
                    message=(f"Segment '{segment}' at {edge} has route {prefix} from segment "
                             f"'{source_segment}' (via {source}), which the policy does not share with it.")))
    return findings


def run(ctx: EvaluationContext) -> list[Finding]:
    return check_cloudwan(ctx)
