# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Transit Gateway collector for one Region (tasks.md 1.13, design.md D§4.2)."""

from __future__ import annotations

from typing import Any

from drift_core.collectors import paginate
from drift_core.snapshot import tags_to_dict

STATE_FILTER = {"Name": "state", "Values": ["active", "blackhole"]}
# Best-effort split used only when the API reports more routes but returns no NextToken
# (older capped behavior). Coverage outside these ranges cannot be guaranteed, so a table
# that needed this split is always marked routes_truncated.
_SPLIT_SUPERNETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def _search(ec2: Any, rtb_id: str, filters: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Page through SearchTransitGatewayRoutes. Returns (routes, capped_without_token)."""
    routes: list[dict[str, Any]] = []
    token: str | None = None
    while True:
        kwargs: dict[str, Any] = {"TransitGatewayRouteTableId": rtb_id, "Filters": filters, "MaxResults": 1000}
        if token:
            kwargs["NextToken"] = token
        page = ec2.search_transit_gateway_routes(**kwargs)
        routes.extend(page.get("Routes") or [])
        token = page.get("NextToken")
        if not token:
            return routes, bool(page.get("AdditionalRoutesAvailable"))


def _route_key(route: dict[str, Any]) -> tuple[str, str]:
    return (route.get("DestinationCidrBlock") or route.get("PrefixListId") or "", route.get("Type") or "")


def search_routes(ec2: Any, rtb_id: str) -> dict[str, Any]:
    """All active + blackhole routes for one table, with the split fallback (D§4.2)."""
    routes, capped = _search(ec2, rtb_id, [STATE_FILTER])
    if not capped:
        return {"routes": routes, "truncated": False}
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for rtype in ("propagated", "static"):
        part, part_capped = _search(ec2, rtb_id, [STATE_FILTER, {"Name": "type", "Values": [rtype]}])
        if part_capped:
            for supernet in _SPLIT_SUPERNETS:
                sub, _ = _search(ec2, rtb_id, [STATE_FILTER, {"Name": "type", "Values": [rtype]},
                                               {"Name": "route-search.subnet-of-match", "Values": [supernet]}])
                part.extend(sub)
        for r in part:
            merged[_route_key(r)] = r
    return {"routes": list(merged.values()), "truncated": True}


def fetch_region(ec2: Any) -> dict[str, Any]:
    """Raw TGW responses for the client's Region."""
    tables = paginate(ec2, "describe_transit_gateway_route_tables", "TransitGatewayRouteTables")
    return {
        "transit_gateways": paginate(ec2, "describe_transit_gateways", "TransitGateways"),
        "route_tables": tables,
        "attachments": paginate(ec2, "describe_transit_gateway_attachments", "TransitGatewayAttachments"),
        "routes": {t["TransitGatewayRouteTableId"]: search_routes(ec2, t["TransitGatewayRouteTableId"])
                   for t in tables if (t.get("State") or "").lower() == "available"},
    }


def fetch_vpn(ec2: Any) -> dict[str, Any]:
    """Site-to-Site VPN connections in the client's Region (check 6 backup health). Not paginated."""
    return {"vpn_connections": ec2.describe_vpn_connections().get("VpnConnections") or []}


def normalize_vpn(raw: dict[str, Any]) -> dict[str, Any]:
    out = []
    for v in raw.get("vpn_connections") or []:
        state = (v.get("State") or "").lower()
        if state in ("deleted", "deleting"):
            continue
        tunnels = v.get("VgwTelemetry") or []
        out.append({"vpn_id": v["VpnConnectionId"], "state": state, "tgw_id": v.get("TransitGatewayId"),
                    "tunnels": len(tunnels),
                    "tunnels_up": sum(1 for t in tunnels if (t.get("Status") or "").upper() == "UP")})
    return {"vpn_connections": out}


def _normalize_route(route: dict[str, Any]) -> dict[str, Any]:
    return {
        "prefix": route.get("DestinationCidrBlock") or route.get("PrefixListId") or "",
        "state": (route.get("State") or "").lower(),
        "type": (route.get("Type") or "").lower(),
        "attachments": [{"attachment_id": a.get("TransitGatewayAttachmentId", ""),
                         "resource_type": (a.get("ResourceType") or "").lower(),
                         "resource_id": a.get("ResourceId", "")}
                        for a in route.get("TransitGatewayAttachments") or []],
    }


def normalize_region(raw: dict[str, Any]) -> dict[str, Any]:
    """Raw TGW responses -> the TGW part of a RegionSnapshot (drift_core.snapshot)."""
    route_results = raw.get("routes") or {}
    tables = []
    for t in raw.get("route_tables") or []:
        rtb_id = t["TransitGatewayRouteTableId"]
        result = route_results.get(rtb_id)
        if result is None:  # table not available: not evaluated, never counted as clean
            continue
        tables.append({"route_table_id": rtb_id, "tgw_id": t.get("TransitGatewayId", ""),
                       "tags": tags_to_dict(t.get("Tags")), "routes_truncated": bool(result.get("truncated")),
                       "routes": [_normalize_route(r) for r in result.get("routes") or []]})
    attachments = []
    for a in raw.get("attachments") or []:
        assoc = a.get("Association")
        attachments.append({
            "attachment_id": a["TransitGatewayAttachmentId"], "tgw_id": a.get("TransitGatewayId", ""),
            "resource_type": (a.get("ResourceType") or "").lower(), "resource_id": a.get("ResourceId", ""),
            "state": (a.get("State") or "").lower(), "tags": tags_to_dict(a.get("Tags")),
            "association": ({"route_table_id": assoc.get("TransitGatewayRouteTableId", ""),
                             "state": (assoc.get("State") or "").lower()} if assoc else None),
        })
    return {
        "transit_gateways": [{"tgw_id": g["TransitGatewayId"], "tags": tags_to_dict(g.get("Tags"))}
                             for g in raw.get("transit_gateways") or []
                             if (g.get("State") or "").lower() not in ("deleted", "deleting")],
        "route_tables": tables,
        "attachments": attachments,
    }
