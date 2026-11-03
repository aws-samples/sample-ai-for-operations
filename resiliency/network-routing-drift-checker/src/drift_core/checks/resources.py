# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Look up and judge the health of resources named in the intent file (checks 4 and 6). Precision code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from drift_core.checks import EvaluationContext


@dataclass(frozen=True)
class ResourceState:
    found: bool
    healthy: bool
    region: str | None  # None when the resource is global (DX gateway) or unknown
    detail: str
    unverifiable: bool = False  # not found, but its collection was incomplete this run


def vifs(ctx: EvaluationContext) -> dict[str, tuple[str, dict[str, Any]]]:
    return {v["vif_id"].lower(): (region, v) for region, snap in ctx.regions.items()
            for v in snap.get("dx_virtual_interfaces") or []}


def vif_health(vif: dict[str, Any]) -> tuple[bool, str]:
    state = vif.get("state", "")
    peers = vif.get("bgp_peers") or []
    up = [p for p in peers if p.get("bgp_status") == "up"]
    if state != "available":
        return False, f"VIF state {state or 'unknown'}"
    if not up:
        return False, "no BGP peer up"
    return True, f"available, {len(up)}/{len(peers)} BGP peer(s) up"


def lookup(value: str, ctx: EvaluationContext) -> ResourceState:
    v = value.lower()
    incomplete = bool(ctx.regions_not_evaluated)
    if v.startswith("dxvif-"):
        hit = vifs(ctx).get(v)
        if hit is None:
            return ResourceState(False, False, None, "VIF not found", unverifiable=incomplete)
        healthy, detail = vif_health(hit[1])
        return ResourceState(True, healthy, hit[0], detail)
    if v.startswith("tgw-attach-"):
        for region, snap in ctx.regions.items():
            for att in snap.get("attachments") or []:
                if att["attachment_id"].lower() == v:
                    state = att.get("state", "")
                    return ResourceState(True, state == "available", region, f"attachment {state}")
        return ResourceState(False, False, None, "attachment not found", unverifiable=incomplete)
    if v.startswith("attachment-"):
        if not ctx.cloudwan:
            return ResourceState(False, False, None, "Cloud WAN not evaluated", unverifiable=True)
        for att in ctx.cloudwan.get("attachments") or []:
            if att["attachment_id"].lower() == v:
                state = (att.get("state") or "").upper()
                return ResourceState(True, state == "AVAILABLE", att.get("edge_location") or None,
                                     f"attachment {state}")
        return ResourceState(False, False, None, "Cloud WAN attachment not found")
    if v.startswith("vpn-"):
        for region, snap in ctx.regions.items():
            for vpn in snap.get("vpn_connections") or []:
                if vpn["vpn_id"].lower() == v:
                    healthy = vpn.get("state") == "available" and vpn.get("tunnels_up", 0) > 0
                    return ResourceState(True, healthy, region,
                                         f"VPN {vpn.get('state')}, {vpn.get('tunnels_up', 0)} tunnel(s) up")
        return ResourceState(False, False, None, "VPN connection not found", unverifiable=incomplete)
    # DX gateway ID: global; healthy while it has an associated gateway.
    associations = [a for snap in ctx.regions.values() for a in snap.get("dx_gateway_associations") or []
                    if a.get("dxgw_id", "").lower() == v]
    if not associations:
        return ResourceState(False, False, None, "DX gateway has no association", unverifiable=incomplete)
    healthy = any(a.get("state") == "associated" for a in associations)
    return ResourceState(True, healthy, None, f"{len(associations)} association(s)")
