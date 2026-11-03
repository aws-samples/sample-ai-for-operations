# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Normalized snapshot shapes: the contract between collectors and checks.

Collectors (data retrieval) turn raw API responses into these dicts and write them to
S3. Checks (precision) read only these shapes, never raw boto3 responses, so the
checks can be tested from recorded fixtures with no network.

CloudWanSnapshot = {
  "core_network_id": str, "global_network_id": str, "home_region": str,
  "policy": dict,                      # the LIVE core network policy document
  "policy_version_id": int | None,
  "attachments": [{
      "attachment_id": str, "attachment_type": str,   # VPC | CONNECT | SITE_TO_SITE_VPN |
                                                      # TRANSIT_GATEWAY_ROUTE_TABLE | DIRECT_CONNECT_GATEWAY
      "edge_location": str, "segment_name": str | None, "state": str,
      "resource_arn": str, "resource_id": str, "owner_account_id": str,
      "tags": {str: str}, "proposed_segment_change": bool,
      "network_function_group": str | None,
  }],
  "route_tables": [{
      "segment": str, "edge": str,
      "routes": [{"prefix": str, "state": "ACTIVE" | "BLACKHOLE", "type": "PROPAGATED" | "STATIC",
                  "destinations": [{"attachment_id": str | None, "segment": str | None, "edge": str | None,
                                    "resource_type": str | None, "resource_id": str | None}]}],
  }],
}

RegionSnapshot = {
  "region": str,
  "transit_gateways": [{"tgw_id": str, "tags": {str: str}}],
  "route_tables": [{
      "route_table_id": str, "tgw_id": str, "tags": {str: str}, "routes_truncated": bool,
      "routes": [{"prefix": str, "state": "active" | "blackhole", "type": "propagated" | "static",
                  "attachments": [{"attachment_id": str, "resource_type": str, "resource_id": str}]}],
  }],
  "attachments": [{
      "attachment_id": str, "tgw_id": str, "resource_type": str, "resource_id": str, "state": str,
      "tags": {str: str}, "association": {"route_table_id": str, "state": str} | None,
  }],
  "dx_virtual_interfaces": [{
      "vif_id": str, "type": str, "state": str, "dxgw_id": str | None, "connection_id": str,
      "prefix_allocation": {"ipv4": int | None, "ipv6": int | None},
      "bgp_peers": [{"peer_id": str, "address_family": str, "bgp_status": str, "state": str}],
  }],
  "dx_gateway_associations": [{
      "association_id": str, "dxgw_id": str, "associated_gateway_id": str,
      "associated_gateway_type": str, "state": str, "allowed_prefixes": [str],
  }],
}

All tag dicts are {key: value} as returned (case preserved); checks apply their own
comparison rules (design.md D§6 for the TGW convention).
"""

from __future__ import annotations

from typing import Any


def tags_to_dict(tags: list[dict[str, Any]] | None, key_name: str = "Key", value_name: str = "Value") -> dict[str, str]:
    """Convert AWS [{Key, Value}] tag lists to a dict. Tolerates None and missing values."""
    result: dict[str, str] = {}
    for tag in tags or []:
        key = tag.get(key_name)
        if key is not None:
            result[str(key)] = str(tag.get(value_name, ""))
    return result


def tag_value(tags: dict[str, str], key: str) -> str | None:
    """Case-insensitive tag-key lookup; returns the trimmed value or None if absent/empty."""
    wanted = key.strip().lower()
    for k, v in tags.items():
        if k.strip().lower() == wanted:
            value = v.strip()
            return value or None
    return None


def ip_family(prefix: str) -> str:
    return "ipv6" if ":" in prefix else "ipv4"
