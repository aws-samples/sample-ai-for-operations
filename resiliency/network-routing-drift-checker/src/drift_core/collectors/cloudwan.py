# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Cloud WAN collector (tasks.md 1.12, design.md D§4.1, D§4.2, D§4.6).

Network Manager is a global service with a single home-Region endpoint (us-west-2 for the
commercial partition; observed in the test account: every client Region resolves to
networkmanager.us-west-2.amazonaws.com). The caller creates the client in the home Region.
"""

from __future__ import annotations

import json
from typing import Any

from drift_core.collectors import paginate
from drift_core.snapshot import tags_to_dict

HOME_REGION = "us-west-2"


def _routes_for(nm: Any, global_network_id: str, core_network_id: str, segment: str, edge: str) -> list[dict]:
    """GetNetworkRoutes is not paginated by the API; it returns the whole table in one call."""
    resp = nm.get_network_routes(
        GlobalNetworkId=global_network_id,
        RouteTableIdentifier={"CoreNetworkSegmentEdge": {"CoreNetworkId": core_network_id,
                                                         "SegmentName": segment, "EdgeLocation": edge}})
    return resp.get("NetworkRoutes") or []


def fetch(nm: Any, core_network_id: str | None = None) -> dict[str, Any] | None:
    """Raw responses for one core network (the first one if none given). None if there is none."""
    if core_network_id is None:
        networks = paginate(nm, "list_core_networks", "CoreNetworks")
        live = [n for n in networks if (n.get("State") or "").upper() not in ("DELETING",)]
        if not live:
            return None
        core_network_id = live[0]["CoreNetworkId"]
    core = nm.get_core_network(CoreNetworkId=core_network_id)["CoreNetwork"]
    policy = nm.get_core_network_policy(CoreNetworkId=core_network_id, Alias="LIVE")["CoreNetworkPolicy"]
    attachments = paginate(nm, "list_attachments", "Attachments", CoreNetworkId=core_network_id)
    tables = []
    for seg in core.get("Segments") or []:
        for edge in seg.get("EdgeLocations") or []:
            tables.append({"segment": seg["Name"], "edge": edge,
                           "routes": _routes_for(nm, core["GlobalNetworkId"], core_network_id, seg["Name"], edge)})
    return {"core_network": core, "policy": policy, "attachments": attachments, "route_tables": tables}


def discover(nm: Any) -> dict[str, Any] | None:
    """Lightweight lookup for Region discovery: the first live core network and its edges."""
    networks = paginate(nm, "list_core_networks", "CoreNetworks")
    live = [n for n in networks if (n.get("State") or "").upper() not in ("DELETING",)]
    if not live:
        return None
    core = nm.get_core_network(CoreNetworkId=live[0]["CoreNetworkId"])["CoreNetwork"]
    return {"core_network_id": core["CoreNetworkId"], "global_network_id": core.get("GlobalNetworkId", ""),
            "home_region": HOME_REGION,
            "edge_locations": sorted(e["EdgeLocation"] for e in core.get("Edges") or [] if e.get("EdgeLocation"))}


def _resource_id(arn: str) -> str:
    """'arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0abc' -> 'vpc-0abc'."""
    tail = arn.rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1]


def edge_regions(raw: dict[str, Any] | None) -> set[str]:
    """Edge locations of the core network (Region discovery input)."""
    if not raw:
        return set()
    return {e["EdgeLocation"] for e in raw["core_network"].get("Edges") or [] if e.get("EdgeLocation")}


def normalize(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Raw Network Manager responses -> CloudWanSnapshot (drift_core.snapshot)."""
    if not raw:
        return None
    core = raw["core_network"]
    policy_doc = raw["policy"].get("PolicyDocument") or "{}"
    policy = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc
    attachments = []
    for a in raw.get("attachments") or []:
        arn = a.get("ResourceArn") or ""
        attachments.append({
            "attachment_id": a["AttachmentId"], "attachment_type": a.get("AttachmentType", ""),
            "edge_location": a.get("EdgeLocation") or "", "segment_name": a.get("SegmentName"),
            "state": a.get("State", ""), "resource_arn": arn, "resource_id": _resource_id(arn) if arn else "",
            "owner_account_id": a.get("OwnerAccountId", ""), "tags": tags_to_dict(a.get("Tags")),
            "proposed_segment_change": bool(a.get("ProposedSegmentChange")),
            "network_function_group": a.get("NetworkFunctionGroupName"),
        })
    tables = []
    for t in raw.get("route_tables") or []:
        routes = []
        for r in t.get("routes") or []:
            routes.append({
                "prefix": r.get("DestinationCidrBlock") or r.get("PrefixListId") or "",
                "state": (r.get("State") or "").upper(), "type": (r.get("Type") or "").upper(),
                "destinations": [{"attachment_id": d.get("CoreNetworkAttachmentId")
                                  or d.get("TransitGatewayAttachmentId"),
                                  "segment": d.get("SegmentName"), "edge": d.get("EdgeLocation"),
                                  "resource_type": (d.get("ResourceType") or "").lower() or None,
                                  "resource_id": d.get("ResourceId")}
                                 for d in r.get("Destinations") or []],
            })
        tables.append({"segment": t["segment"], "edge": t["edge"], "routes": routes})
    return {
        "core_network_id": core["CoreNetworkId"], "global_network_id": core.get("GlobalNetworkId", ""),
        "home_region": HOME_REGION, "policy": policy, "policy_version_id": raw["policy"].get("PolicyVersionId"),
        "attachments": attachments, "route_tables": tables,
    }
