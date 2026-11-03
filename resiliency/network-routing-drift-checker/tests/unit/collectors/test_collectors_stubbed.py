# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Collector paths the lab account cannot exercise, validated by botocore Stubber.

Stubber rejects any request parameter or response field that does not match the pinned
service model (botocore 1.43.111), so these fixtures are guaranteed to be valid shapes.
"""

import json

import boto3
import pytest
from botocore.stub import Stubber

from drift_core.collectors import cloudwan, directconnect, tgw
from drift_core.regions import enabled_regions, has_transit_gateway, resolve_scope

RTB = "tgw-rtb-0000000000000000a"


def client(service, region="eu-central-1"):
    return boto3.client(service, region_name=region, aws_access_key_id="x", aws_secret_access_key="x")  # nosec B106 -- placeholder creds for a Stubber-backed client, never makes a real call


def route(cidr, att="tgw-attach-0000000000000001", rtype="propagated", state="active", rt="vpc"):
    r = {"DestinationCidrBlock": cidr, "Type": rtype, "State": state}
    if att:
        r["TransitGatewayAttachments"] = [{"TransitGatewayAttachmentId": att, "ResourceType": rt,
                                           "ResourceId": "vpc-0000000000000001"}]
    return r


STATE = {"Name": "state", "Values": ["active", "blackhole"]}


def test_search_routes_follows_next_token():
    ec2 = client("ec2")
    with Stubber(ec2) as st:
        st.add_response("search_transit_gateway_routes",
                        {"Routes": [route("10.0.0.0/16")], "NextToken": "t1", "AdditionalRoutesAvailable": True},
                        {"TransitGatewayRouteTableId": RTB, "Filters": [STATE], "MaxResults": 1000})
        st.add_response("search_transit_gateway_routes",
                        {"Routes": [route("10.1.0.0/16")], "AdditionalRoutesAvailable": False},
                        {"TransitGatewayRouteTableId": RTB, "Filters": [STATE], "MaxResults": 1000,
                         "NextToken": "t1"})
        out = tgw.search_routes(ec2, RTB)
    assert [r["DestinationCidrBlock"] for r in out["routes"]] == ["10.0.0.0/16", "10.1.0.0/16"]
    assert out["truncated"] is False


def test_search_routes_capped_without_token_splits_and_marks_truncated():
    ec2 = client("ec2")
    capped = {"Routes": [route("10.0.0.0/16")], "AdditionalRoutesAvailable": True}
    with Stubber(ec2) as st:
        st.add_response("search_transit_gateway_routes", capped,
                        {"TransitGatewayRouteTableId": RTB, "Filters": [STATE], "MaxResults": 1000})
        st.add_response("search_transit_gateway_routes", {"Routes": [route("10.0.0.0/16"), route("10.2.0.0/16")],
                                                          "AdditionalRoutesAvailable": False},
                        {"TransitGatewayRouteTableId": RTB, "MaxResults": 1000,
                         "Filters": [STATE, {"Name": "type", "Values": ["propagated"]}]})
        st.add_response("search_transit_gateway_routes", capped,
                        {"TransitGatewayRouteTableId": RTB, "MaxResults": 1000,
                         "Filters": [STATE, {"Name": "type", "Values": ["static"]}]})
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            st.add_response("search_transit_gateway_routes",
                            {"Routes": [route("192.168.9.0/24", rtype="static")] if net.startswith("192") else [],
                             "AdditionalRoutesAvailable": False},
                            {"TransitGatewayRouteTableId": RTB, "MaxResults": 1000,
                             "Filters": [STATE, {"Name": "type", "Values": ["static"]},
                                         {"Name": "route-search.subnet-of-match", "Values": [net]}]})
        out = tgw.search_routes(ec2, RTB)
    assert out["truncated"] is True
    assert sorted({r["DestinationCidrBlock"] for r in out["routes"]}) == ["10.0.0.0/16", "10.2.0.0/16",
                                                                         "192.168.9.0/24"]


def test_fetch_region_skips_non_available_tables_and_normalize_drops_them():
    ec2 = client("ec2")
    with Stubber(ec2) as st:
        st.add_response("describe_transit_gateway_route_tables", {"TransitGatewayRouteTables": [
            {"TransitGatewayRouteTableId": RTB, "TransitGatewayId": "tgw-0000000000000001", "State": "available",
             "Tags": [{"Key": "Environment", "Value": "prod"}]},
            {"TransitGatewayRouteTableId": "tgw-rtb-0000000000000000b", "TransitGatewayId": "tgw-0000000000000001",
             "State": "pending"}]}, {})
        st.add_response("describe_transit_gateways", {"TransitGateways": [
            {"TransitGatewayId": "tgw-0000000000000001", "State": "available"},
            {"TransitGatewayId": "tgw-0000000000000002", "State": "deleted"}]}, {})
        st.add_response("describe_transit_gateway_attachments", {"TransitGatewayAttachments": [
            {"TransitGatewayAttachmentId": "tgw-attach-0000000000000001", "TransitGatewayId": "tgw-0000000000000001",
             "ResourceType": "vpc", "ResourceId": "vpc-0000000000000001", "State": "available",
             "Association": {"TransitGatewayRouteTableId": RTB, "State": "associated"},
             "Tags": [{"Key": "Environment", "Value": "prod"}]},
            {"TransitGatewayAttachmentId": "tgw-attach-0000000000000002", "TransitGatewayId": "tgw-0000000000000001",
             "ResourceType": "direct-connect-gateway", "ResourceId": "dxgw-x", "State": "available"}]}, {})
        st.add_response("search_transit_gateway_routes", {"Routes": [route("10.0.0.0/16")]},
                        {"TransitGatewayRouteTableId": RTB, "Filters": [STATE], "MaxResults": 1000})
        raw = tgw.fetch_region(ec2)
    snap = tgw.normalize_region(json.loads(json.dumps(raw, default=str)))
    assert [t["route_table_id"] for t in snap["route_tables"]] == [RTB]
    assert snap["route_tables"][0]["tags"] == {"Environment": "prod"}
    assert [g["tgw_id"] for g in snap["transit_gateways"]] == ["tgw-0000000000000001"]
    assert snap["attachments"][1]["association"] is None
    assert snap["attachments"][0]["association"] == {"route_table_id": RTB, "state": "associated"}


def test_dx_vifs_with_allocation_bgp_and_associations_attributed_to_region():
    dx = client("directconnect")
    vif = {"virtualInterfaceId": "dxvif-00000001", "virtualInterfaceType": "transit",
           "virtualInterfaceState": "available", "directConnectGatewayId": "00000001-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
           "connectionId": "dxcon-00000001", "prefixPoolAllocatedCountIpv4": 500,
           "bgpPeers": [{"bgpPeerId": "dxpeer-1", "addressFamily": "ipv4", "bgpStatus": "down",
                         "bgpPeerState": "available", "authKey": "x"}]}
    gone = dict(vif, virtualInterfaceId="dxvif-00000002", virtualInterfaceState="deleted")
    with Stubber(dx) as st:
        st.add_response("describe_virtual_interfaces", {"virtualInterfaces": [vif, gone]}, {})
        region_raw = directconnect.fetch_region(dx)
    gw_id = "00000001-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    gateways_raw = {"gateways": [{"directConnectGatewayId": gw_id}], "associations": [
        {"associationId": "a-1", "directConnectGatewayId": gw_id, "associationState": "associated",
         "associatedGateway": {"id": "tgw-0000000000000001", "type": "transitGateway", "region": "eu-central-1"},
         "allowedPrefixesToDirectConnectGateway": [{"cidr": "10.0.0.0/16"}, {"cidr": "10.0.0.0/16"}]},
        {"associationId": "a-2", "directConnectGatewayId": gw_id, "associationState": "associated",
         "virtualGatewayId": "vgw-1", "virtualGatewayRegion": "eu-west-1"},
        {"associationId": "a-3", "directConnectGatewayId": gw_id, "associationState": "disassociated",
         "associatedGateway": {"id": "tgw-9", "type": "transitGateway", "region": "us-east-1"}}]}
    snap = directconnect.normalize_region("eu-central-1", region_raw, gateways_raw)
    assert [v["vif_id"] for v in snap["dx_virtual_interfaces"]] == ["dxvif-00000001"]
    v = snap["dx_virtual_interfaces"][0]
    assert v["prefix_allocation"] == {"ipv4": 500, "ipv6": None}
    assert v["bgp_peers"] == [{"peer_id": "dxpeer-1", "address_family": "ipv4", "bgp_status": "down",
                               "state": "available"}]
    assert [a["association_id"] for a in snap["dx_gateway_associations"]] == ["a-1"]
    assert snap["dx_gateway_associations"][0]["allowed_prefixes"] == ["10.0.0.0/16"]
    west = directconnect.normalize_region("eu-west-1", {"virtual_interfaces": []}, gateways_raw)
    assert west["dx_gateway_associations"][0]["associated_gateway_type"] == "virtualPrivateGateway"
    assert directconnect.association_regions(gateways_raw) == {"eu-central-1", "eu-west-1"}


def test_dx_fetch_gateways_paginates_associations_per_gateway():
    dx = client("directconnect")
    gw = "00000001-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    with Stubber(dx) as st:
        st.add_response("describe_direct_connect_gateways", {"directConnectGateways": [
            {"directConnectGatewayId": gw}]}, {})
        st.add_response("describe_direct_connect_gateway_associations", {
            "directConnectGatewayAssociations": [{"associationId": "a-1"}]}, {"directConnectGatewayId": gw})
        out = directconnect.fetch_gateways(dx)
    assert [a["associationId"] for a in out["associations"]] == ["a-1"]


POLICY_DOC = json.dumps({"version": "2021.12", "segments": [{"name": "prod"}, {"name": "dev"}],
                         "attachment-policies": [{"rule-number": 1, "conditions": [{"type": "any"}],
                                                  "action": {"association-method": "tag",
                                                             "tag-value-of-key": "Environment"}}]})
CN = "core-network-0000000000000001"
GN = "global-network-0000000000000001"


def test_cloudwan_fetch_and_normalize_with_attachments_and_routes():
    nm = client("networkmanager", "us-west-2")
    with Stubber(nm) as st:
        st.add_response("list_core_networks", {"CoreNetworks": [
            {"CoreNetworkId": "core-network-0000000000000009", "State": "DELETING"},
            {"CoreNetworkId": CN, "State": "AVAILABLE"}]}, {})
        st.add_response("get_core_network", {"CoreNetwork": {
            "CoreNetworkId": CN, "GlobalNetworkId": GN, "State": "AVAILABLE",
            "Edges": [{"EdgeLocation": "eu-central-1"}],
            "Segments": [{"Name": "prod", "EdgeLocations": ["eu-central-1"]}]}}, {"CoreNetworkId": CN})
        st.add_response("get_core_network_policy", {"CoreNetworkPolicy": {
            "CoreNetworkId": CN, "PolicyVersionId": 3, "PolicyDocument": POLICY_DOC}},
            {"CoreNetworkId": CN, "Alias": "LIVE"})
        st.add_response("list_attachments", {"Attachments": [{
            "AttachmentId": "attachment-0000000000000001", "AttachmentType": "VPC", "State": "AVAILABLE",
            "EdgeLocation": "eu-central-1", "SegmentName": "dev", "OwnerAccountId": "123456789012",
            "ResourceArn": "arn:aws:ec2:eu-central-1:123456789012:vpc/vpc-0000000000000001",
            "Tags": [{"Key": "Environment", "Value": "prod"}],
            "ProposedSegmentChange": {"SegmentName": "prod"}}]}, {"CoreNetworkId": CN})
        st.add_response("get_network_routes", {"NetworkRoutes": [{
            "DestinationCidrBlock": "10.9.0.0/16", "State": "BLACKHOLE", "Type": "STATIC",
            "Destinations": [{"CoreNetworkAttachmentId": "attachment-0000000000000001", "SegmentName": "dev",
                              "EdgeLocation": "eu-central-1", "ResourceType": "vpc",
                              "ResourceId": "vpc-0000000000000001"}]}]},
            {"GlobalNetworkId": GN, "RouteTableIdentifier": {"CoreNetworkSegmentEdge": {
                "CoreNetworkId": CN, "SegmentName": "prod", "EdgeLocation": "eu-central-1"}}})
        raw = cloudwan.fetch(nm)
    snap = cloudwan.normalize(json.loads(json.dumps(raw, default=str)))
    att = snap["attachments"][0]
    assert att["resource_id"] == "vpc-0000000000000001" and att["tags"] == {"Environment": "prod"}
    assert att["proposed_segment_change"] is True and snap["policy_version_id"] == 3
    r = snap["route_tables"][0]["routes"][0]
    assert r["state"] == "BLACKHOLE" and r["destinations"][0]["attachment_id"] == "attachment-0000000000000001"
    assert cloudwan.edge_regions(raw) == {"eu-central-1"}


def test_cloudwan_none_when_no_core_network():
    nm = client("networkmanager", "us-west-2")
    with Stubber(nm) as st:
        st.add_response("list_core_networks", {"CoreNetworks": []}, {})
        assert cloudwan.fetch(nm) is None
    assert cloudwan.normalize(None) is None and cloudwan.edge_regions(None) == set()


def test_region_discovery_helpers():
    ec2 = client("ec2", "us-east-1")
    with Stubber(ec2) as st:
        st.add_response("describe_regions", {"Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "eu-central-1"}]},
                        {"Filters": [{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]})
        st.add_response("describe_transit_gateways", {"TransitGateways": [{"TransitGatewayId": "tgw-1",
                                                                           "State": "deleted"}]}, {"MaxResults": 5})
        assert enabled_regions(ec2) == ["eu-central-1", "eu-west-1"]
        assert has_transit_gateway(ec2) is False


@pytest.mark.parametrize("kwargs,expected", [
    ({}, (("eu-central-1", "eu-west-1", "us-east-1"), (), "discovered")),
    ({"exclude": ("eu-west-1",)}, (("eu-central-1", "us-east-1"), ("eu-west-1",), "discovered")),
    ({"allowlist": ("eu-west-1", "ap-south-9")}, (("eu-west-1",), (), "allowlist")),
    ({"allowlist": ("eu-west-1",), "override": ("us-east-1",)}, (("us-east-1",), (), "override")),
])
def test_resolve_scope(kwargs, expected):
    scope = resolve_scope(["eu-central-1", "eu-west-1", "us-east-1"], {"eu-central-1"}, {"us-east-1"},
                          {"eu-west-1"}, **kwargs)
    assert (scope.evaluate, scope.excluded, scope.source) == expected
