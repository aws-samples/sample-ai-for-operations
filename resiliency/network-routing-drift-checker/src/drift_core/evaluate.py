# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Run the drift checks over one run's snapshots (tasks.md 1.22, 2.2-2.4). Precision code.

Adds the `system` findings that make incompleteness visible: a Region, Cloud WAN, or the
global DX gateway list that could not be collected, a route table whose routes were
truncated, and an intent file that could not be used. None of these is ever silently clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from drift_core.checks import (
    EvaluationContext,
    check1_domain,
    check2_leak,
    check2_tgw,
    check3_blackhole,
    check4_redundancy,
    check5_limits,
    check6_hybrid_path,
)
from drift_core.finding import Finding, dedupe
from drift_core.intent import resolve_isolation

# The six checks of requirements §5, with what this build evaluates.
PHASE1_CHECKS = (
    ("check1", "Attachment in wrong routing domain (Cloud WAN + TGW)", check1_domain.run),
    ("check2", "Prefix leak between routing domains (Cloud WAN)", check2_leak.run),
    ("check3", "Blackhole routes", check3_blackhole.run),
    ("check5", "Route / prefix counts approaching a limit", check5_limits.run),
)
# Intent-dependent checks (requirements §5, Phase 2). Run only with a valid intent file.
INTENT_CHECKS = (
    ("check2-tgw", "Prefix leak between TGW route tables (isolation matrix)", check2_tgw.run),
    ("check4", "Direct Connect redundancy", check4_redundancy.run),
    ("check6", "Hybrid path intent", check6_hybrid_path.run),
)


@dataclass
class EvaluationResult:
    findings: list[Finding]
    checks_run: list[str]
    checks_skipped: list[str]
    skip_reason: str | None
    resources_evaluated: int
    regions_evaluated: list[str] = field(default_factory=list)
    regions_not_evaluated: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "checks_run": self.checks_run,
            "checks_skipped": self.checks_skipped,
            "skip_reason": self.skip_reason,
            "resources_evaluated": self.resources_evaluated,
            "regions_evaluated": self.regions_evaluated,
            "regions_not_evaluated": self.regions_not_evaluated,
        }


def _system(kind: str, region: str, identity: tuple[str, ...], message: str, **context: Any) -> Finding:
    return Finding(check="system", kind=kind, severity="system", region=region, identity=identity,
                   context=context, message=message)


def count_resources(cloudwan: dict[str, Any] | None, regions: dict[str, dict[str, Any]]) -> int:
    total = 0
    if cloudwan:
        total += len(cloudwan.get("attachments") or []) + len(cloudwan.get("route_tables") or [])
    for snap in regions.values():
        for key in ("transit_gateways", "route_tables", "attachments", "dx_virtual_interfaces",
                    "dx_gateway_associations", "vpn_connections"):
            total += len(snap.get(key) or [])
    return total


def intent_skip_reason(intent_status: str) -> str | None:
    """Why intent-dependent checks are skipped, or None if they run."""
    return {
        "absent": "intent file absent",
        "rejected": "intent file rejected",
        "unreadable": "intent file unreadable",
        "ok": None,
    }.get(intent_status, f"intent status {intent_status}")


def _usable_intent(manifest: dict[str, Any], regions: dict[str, dict[str, Any]], not_evaluated: dict[str, str]
                   ) -> tuple[str, list[str], dict[str, Any] | None]:
    """(status, errors, model). A valid file whose isolation names don't resolve becomes 'rejected'.
    The name check is skipped when a Region was not evaluated: its tables may simply be missing."""
    intent = manifest.get("intent") or {}
    status, errors = intent.get("status", "absent"), list(intent.get("errors") or [])
    model = intent.get("model") if status == "ok" else None
    if model and not not_evaluated:
        semantic = resolve_isolation(model, regions, manifest.get("tag_key", "Environment"))
        if semantic:
            return "rejected", semantic, None
    return status, errors, model


def evaluate(cloudwan: dict[str, Any] | None, regions: dict[str, dict[str, Any]], manifest: dict[str, Any],
             not_evaluated: dict[str, str], cloudwan_error: str | None = None) -> EvaluationResult:
    """Run every applicable check and add system findings for anything not fully evaluated."""
    status, errors, model = _usable_intent(manifest, regions, not_evaluated)
    ctx = EvaluationContext(
        cloudwan=cloudwan, regions=regions, intent=model, regions_not_evaluated=frozenset(not_evaluated),
        environment_tag_key=manifest.get("tag_key", "Environment"),
        limit_threshold_percent=float(manifest.get("limit_threshold_percent", 80.0)),
        limit_threshold_overrides=dict(manifest.get("limit_threshold_overrides") or {}),
    )
    active = PHASE1_CHECKS + (INTENT_CHECKS if model is not None else ())
    findings: list[Finding] = []
    for _, _, run in active:
        findings.extend(run(ctx))

    for region, reason in sorted(not_evaluated.items()):
        findings.append(_system("region-not-evaluated", region, (region,),
                                f"Region {region} not evaluated: {reason}", reason=reason))
    if cloudwan_error:
        findings.append(_system("cloudwan-not-evaluated", "global", ("cloudwan",),
                                f"Cloud WAN not evaluated: {cloudwan_error}", reason=cloudwan_error))
    dx_status = (manifest.get("dx_gateways") or {}).get("status", "ok")
    if dx_status != "ok":
        reason = (manifest.get("dx_gateways") or {}).get("error", dx_status)
        findings.append(_system("dx-gateways-not-evaluated", "global", ("dx-gateways",),
                                f"Direct Connect gateway associations not evaluated: {reason}", reason=reason))
    for region, snap in sorted(regions.items()):
        for table in snap.get("route_tables") or []:
            if table.get("routes_truncated"):
                rtb = table["route_table_id"]
                findings.append(_system("routes-truncated", region, (rtb,),
                                        f"Route table {rtb} returned an incomplete route list; it is not fully "
                                        "evaluated.", route_table_id=rtb))
    if status in ("rejected", "unreadable"):
        detail = "; ".join(errors) if errors else status
        findings.append(_system(f"intent-file-{status}", "global", ("intent-file",),
                                f"Intent file {status}: {detail}. Intent-dependent checks are not enforced.",
                                errors=errors))

    return EvaluationResult(
        findings=dedupe(findings),
        checks_run=[name for name, _, _ in active],
        checks_skipped=[] if model is not None else [name for name, _, _ in INTENT_CHECKS],
        skip_reason=intent_skip_reason(status),
        resources_evaluated=count_resources(cloudwan, regions),
        regions_evaluated=sorted(regions),
        regions_not_evaluated=dict(sorted(not_evaluated.items())),
    )
