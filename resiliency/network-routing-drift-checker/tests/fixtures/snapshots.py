# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Normalized snapshot builders for check tests (shape: src/drift_core/snapshot.py).

Account IDs, ARNs and resource IDs are placeholders.
"""

from __future__ import annotations

import copy

ACCOUNT = "123456789012"
CORE = "core-network-0abc123"

POLICY = {
    "version": "2021.12",
    "core-network-configuration": {"asn-ranges": ["64512-64555"],
                                   "edge-locations": [{"location": "eu-central-1"}, {"location": "eu-west-1"}]},
    "segments": [{"name": "prod"}, {"name": "dev"}, {"name": "shared"}, {"name": "hybrid"}],
    "attachment-policies": [
        {"rule-number": 100, "condition-logic": "or",
         "conditions": [{"type": "attachment-type", "operator": "equals", "value": "direct-connect-gateway"}],
         "action": {"association-method": "constant", "segment": "hybrid"}},
        {"rule-number": 200, "conditions": [{"type": "tag-exists", "key": "Environment"}],
         "action": {"association-method": "tag", "tag-value-of-key": "Environment"}},
    ],
    "segment-actions": [
        {"action": "share", "mode": "attachment-route", "segment": "shared", "share-with": "*"},
        {"action": "share", "mode": "attachment-route", "segment": "hybrid", "share-with": ["prod"]},
        {"action": "create-route", "segment": "dev", "destination-cidr-blocks": ["10.250.0.0/16"],
         "destinations": ["attachment-0hyb"]},
    ],
}


def cw_attachment(aid, segment, env=None, atype="VPC", edge="eu-central-1", state="AVAILABLE", **over):
    tags = {"Environment": env} if env else {}
    att = {"attachment_id": aid, "attachment_type": atype, "edge_location": edge, "segment_name": segment,
           "state": state, "resource_arn": f"arn:aws:ec2:{edge}:{ACCOUNT}:vpc/vpc-{aid[-4:]}",
           "resource_id": f"vpc-{aid[-4:]}", "owner_account_id": ACCOUNT, "tags": tags,
           "proposed_segment_change": False, "network_function_group": None}
    att.update(over)
    return att


def cw_route(prefix, dest_segment, dest_attachment, state="ACTIVE", rtype="PROPAGATED", resource_type="vpc",
             resource_id=None):
    return {"prefix": prefix, "state": state, "type": rtype,
            "destinations": [{"attachment_id": dest_attachment, "segment": dest_segment, "edge": "eu-central-1",
                              "resource_type": resource_type, "resource_id": resource_id}]}


def cloudwan(attachments=None, route_tables=None, policy=None):
    return {"core_network_id": CORE, "global_network_id": "global-network-0g1", "home_region": "eu-west-1",
            "policy": copy.deepcopy(policy or POLICY), "policy_version_id": 7,
            "attachments": attachments or [], "route_tables": route_tables or []}


def clean_cloudwan():
    """No drift: attachments in their policy segments, only shared/own routes visible."""
    atts = [cw_attachment("attachment-0prd", "prod", "prod"), cw_attachment("attachment-0dev", "dev", "dev"),
            cw_attachment("attachment-0shr", "shared", "shared"),
            cw_attachment("attachment-0hyb", "hybrid", atype="DIRECT_CONNECT_GATEWAY",
                          resource_id="dxgw-0aaa")]
    tables = [
        {"segment": "prod", "edge": "eu-central-1", "routes": [
            cw_route("10.1.0.0/16", "prod", "attachment-0prd"),
            cw_route("10.3.0.0/16", "shared", "attachment-0shr"),
            cw_route("192.168.0.0/16", "hybrid", "attachment-0hyb", resource_type="direct-connect-gateway",
                     resource_id="dxgw-0aaa")]},
        {"segment": "dev", "edge": "eu-central-1", "routes": [
            cw_route("10.2.0.0/16", "dev", "attachment-0dev"),
            cw_route("10.3.0.0/16", "shared", "attachment-0shr"),
            cw_route("10.250.0.0/16", "hybrid", "attachment-0hyb", rtype="STATIC")]},
    ]
    return cloudwan(atts, tables)


def tgw_table(rtb_id, env=None, routes=None, tgw_id="tgw-0aaa", truncated=False):
    return {"route_table_id": rtb_id, "tgw_id": tgw_id, "tags": {"Environment": env} if env else {},
            "routes_truncated": truncated, "routes": routes or []}


def tgw_route(prefix, attachment_id, resource_type="vpc", resource_id="vpc-0x", state="active", rtype="propagated"):
    return {"prefix": prefix, "state": state, "type": rtype,
            "attachments": [{"attachment_id": attachment_id, "resource_type": resource_type,
                             "resource_id": resource_id}]}


def tgw_attachment(aid, env, rtb_id, resource_type="vpc", state="available", assoc_state="associated",
                   tgw_id="tgw-0aaa", resource_id=None):
    return {"attachment_id": aid, "tgw_id": tgw_id, "resource_type": resource_type,
            "resource_id": resource_id or f"vpc-{aid[-4:]}", "state": state,
            "tags": {"Environment": env} if env else {},
            "association": {"route_table_id": rtb_id, "state": assoc_state} if rtb_id else None}


def vif(vif_id, dxgw_id="dxgw-0aaa", ipv4=None, ipv6=None, vtype="transit", state="available", bgp="up"):
    return {"vif_id": vif_id, "type": vtype, "state": state, "dxgw_id": dxgw_id, "connection_id": "dxcon-0abc",
            "prefix_allocation": {"ipv4": ipv4, "ipv6": ipv6},
            "bgp_peers": [{"peer_id": f"{vif_id}-p1", "address_family": "ipv4", "bgp_status": bgp,
                           "state": "available"}]}


def region(name="eu-central-1", route_tables=None, attachments=None, vifs=None, associations=None):
    return {"region": name, "transit_gateways": [{"tgw_id": "tgw-0aaa", "tags": {}}],
            "route_tables": route_tables or [], "attachments": attachments or [],
            "dx_virtual_interfaces": vifs or [], "dx_gateway_associations": associations or []}


def clean_region(name="eu-central-1"):
    return region(
        name=name,
        route_tables=[
            tgw_table("tgw-rtb-0prd", "prod", [tgw_route("10.1.0.0/16", "tgw-attach-0prd")]),
            tgw_table("tgw-rtb-0dev", "dev", [tgw_route("10.2.0.0/16", "tgw-attach-0dev")]),
        ],
        attachments=[tgw_attachment("tgw-attach-0prd", "prod", "tgw-rtb-0prd"),
                     tgw_attachment("tgw-attach-0dev", "Dev ", "tgw-rtb-0dev")],
    )
