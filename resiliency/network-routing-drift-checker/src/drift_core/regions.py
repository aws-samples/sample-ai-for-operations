# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Region scope resolution (tasks.md 1.11, requirements §9.1). Precision code over discovery inputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegionScope:
    evaluate: tuple[str, ...]
    excluded: tuple[str, ...]
    source: str  # "discovered" | "allowlist" | "override"


def enabled_regions(ec2: Any) -> list[str]:
    """Enabled Regions only (requirements §9.1). Data retrieval."""
    resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    return sorted(r["RegionName"] for r in resp.get("Regions") or [])


def has_transit_gateway(ec2: Any) -> bool:
    """True if the client's Region has at least one non-deleted TGW. Data retrieval."""
    resp = ec2.describe_transit_gateways(MaxResults=5)
    return any((g.get("State") or "").lower() not in ("deleted", "deleting") for g in resp.get("TransitGateways") or [])


def resolve_scope(enabled: list[str], tgw_regions: set[str], cloudwan_edges: set[str], dx_association_regions: set[str],
                  allowlist: tuple[str, ...] = (), exclude: tuple[str, ...] = (),
                  override: tuple[str, ...] | None = None) -> RegionScope:
    """Apply override > allowlist > discovery, then the exclude list. Unknown/disabled Regions are dropped."""
    enabled_set = set(enabled)
    if override:
        source, chosen = "override", set(override)
    elif allowlist:
        source, chosen = "allowlist", set(allowlist)
    else:
        source, chosen = "discovered", tgw_regions | cloudwan_edges | dx_association_regions
    chosen &= enabled_set
    excluded = tuple(sorted(chosen & set(exclude)))
    return RegionScope(evaluate=tuple(sorted(chosen - set(exclude))), excluded=excluded, source=source)
