# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Direct Connect collector (tasks.md 1.14, design.md D§4.4, D§4.5).

VIFs are Regional. DX gateways and their associations are global: every Regional endpoint
returns the same set. Associations are therefore attributed to the Region of their
associated gateway, so each one appears in exactly one RegionSnapshot.
"""

from __future__ import annotations

from typing import Any

from drift_core.collectors import paginate


def fetch_gateways(dx: Any) -> dict[str, Any]:
    """Global: all DX gateways and every association of each (call once per run)."""
    gateways = paginate(dx, "describe_direct_connect_gateways", "directConnectGateways")
    associations: list[dict[str, Any]] = []
    for gw in gateways:
        associations.extend(paginate(dx, "describe_direct_connect_gateway_associations",
                                     "directConnectGatewayAssociations",
                                     directConnectGatewayId=gw["directConnectGatewayId"]))
    return {"gateways": gateways, "associations": associations}


def fetch_region(dx: Any) -> dict[str, Any]:
    """Regional: virtual interfaces owned in the client's Region (not paginated by the API)."""
    return {"virtual_interfaces": dx.describe_virtual_interfaces().get("virtualInterfaces") or []}


def association_regions(gateways_raw: dict[str, Any]) -> set[str]:
    """Regions that host a TGW or VGW associated with a DX gateway (Region discovery input)."""
    regions: set[str] = set()
    for a in gateways_raw.get("associations") or []:
        if (a.get("associationState") or "").lower() in ("disassociated", "disassociating"):
            continue
        region = (a.get("associatedGateway") or {}).get("region") or a.get("virtualGatewayRegion")
        if region:
            regions.add(region)
    return regions


def _normalize_vif(v: dict[str, Any]) -> dict[str, Any]:
    return {
        "vif_id": v["virtualInterfaceId"],
        "type": (v.get("virtualInterfaceType") or "").lower(),
        "state": (v.get("virtualInterfaceState") or "").lower(),
        "dxgw_id": v.get("directConnectGatewayId") or None,
        "connection_id": v.get("connectionId", ""),
        # Verified field names (tasks.md 0.2). Absent -> None -> check 5 uses assumed-default.
        "prefix_allocation": {"ipv4": v.get("prefixPoolAllocatedCountIpv4"),
                              "ipv6": v.get("prefixPoolAllocatedCountIpv6")},
        "bgp_peers": [{"peer_id": p.get("bgpPeerId", ""), "address_family": (p.get("addressFamily") or "").lower(),
                       "bgp_status": (p.get("bgpStatus") or "").lower(),
                       "state": (p.get("bgpPeerState") or "").lower()}
                      for p in v.get("bgpPeers") or []],
    }


def _normalize_association(a: dict[str, Any]) -> dict[str, Any]:
    gw = a.get("associatedGateway") or {}
    return {
        "association_id": a.get("associationId", ""),
        "dxgw_id": a.get("directConnectGatewayId", ""),
        "associated_gateway_id": gw.get("id") or a.get("virtualGatewayId", ""),
        "associated_gateway_type": gw.get("type") or ("virtualPrivateGateway" if a.get("virtualGatewayId") else ""),
        "state": (a.get("associationState") or "").lower(),
        "allowed_prefixes": sorted({p.get("cidr", "") for p in a.get("allowedPrefixesToDirectConnectGateway") or []
                                    if p.get("cidr")}),
    }


def normalize_region(region: str, region_raw: dict[str, Any], gateways_raw: dict[str, Any]) -> dict[str, Any]:
    """Raw DX responses -> the DX part of a RegionSnapshot for `region`."""
    associations = []
    for a in gateways_raw.get("associations") or []:
        home = (a.get("associatedGateway") or {}).get("region") or a.get("virtualGatewayRegion")
        if home == region and (a.get("associationState") or "").lower() not in ("disassociated", "disassociating"):
            associations.append(_normalize_association(a))
    return {
        "dx_virtual_interfaces": [_normalize_vif(v) for v in region_raw.get("virtual_interfaces") or []
                                  if (v.get("virtualInterfaceState") or "").lower() != "deleted"],
        "dx_gateway_associations": associations,
    }
