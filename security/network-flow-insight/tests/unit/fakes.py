# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Fakes for AWS clients. ``FakeSession`` renders an inventory document back into EC2 Describe* responses."""

from __future__ import annotations


class _Paginator:
    def __init__(self, fn):
        self._fn = fn

    def paginate(self, **kw):
        yield self._fn(**kw)


class FakeEc2:
    def __init__(self, doc: dict, account_id: str, region: str) -> None:
        self.d = doc
        self.account = account_id
        self.region = region

    def get_paginator(self, op: str):
        return _Paginator(getattr(self, op))

    def describe_vpcs(self, **_):
        return {
            "Vpcs": [
                {
                    "VpcId": v["id"],
                    "CidrBlock": v["cidrs"][0],
                    "CidrBlockAssociationSet": [
                        {"CidrBlock": c, "CidrBlockState": {"State": "associated"}} for c in v["cidrs"]
                    ],
                }
                for v in self.d["vpcs"]
                if v["account_id"] == self.account and v["region"] == self.region
            ]
        }

    def _vpcs(self):
        return {
            v["id"] for v in self.d["vpcs"] if v["account_id"] == self.account and v["region"] == self.region
        }

    def describe_subnets(self, **_):
        return {
            "Subnets": [
                {
                    "SubnetId": s["id"],
                    "VpcId": s["vpc_id"],
                    "AvailabilityZoneId": s["az"],
                    "AvailabilityZone": s["az"],
                    "CidrBlock": s["cidr"],
                }
                for s in self.d["subnets"]
                if s["vpc_id"] in self._vpcs()
            ]
        }

    def describe_route_tables(self, **_):
        out = []
        for rt in self.d["route_tables"]:
            if rt["vpc_id"] not in self._vpcs():
                continue
            routes = []
            for r in rt["routes"]:
                e = {"State": "active"}
                if "destination" in r:
                    e["DestinationCidrBlock"] = r["destination"]
                else:
                    e["DestinationPrefixListId"] = r["prefix_list_id"]
                t, i = r["target_type"], r["target_id"]
                if t == "nat-gateway":
                    e["NatGatewayId"] = i
                elif t == "transit-gateway":
                    e["TransitGatewayId"] = i
                else:
                    e["GatewayId"] = i
                routes.append(e)
            assoc = [{"Main": True}] if rt["main"] else []
            assoc += [
                {"SubnetId": s["id"]}
                for s in self.d["subnets"]
                if s["route_table_id"] == rt["id"] and not rt["main"]
            ]
            out.append(
                {"RouteTableId": rt["id"], "VpcId": rt["vpc_id"], "Routes": routes, "Associations": assoc}
            )
        return {"RouteTables": out}

    def describe_network_interfaces(self, **_):
        itype = {"nat-gateway": "nat_gateway", "interface-endpoint": "vpc_endpoint", "workload": "interface"}
        return {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": i["id"],
                    "VpcId": i["vpc_id"],
                    "SubnetId": i["subnet_id"],
                    "AvailabilityZone": i["az"],
                    "InterfaceType": itype[i["role"]],
                    "Description": i["description"],
                    "PrivateIpAddresses": [{"PrivateIpAddress": ip} for ip in i["private_ips"]],
                }
                for i in self.d["interfaces"]
                if i["account_id"] == self.account and i["region"] == self.region
            ]
        }

    def describe_nat_gateways(self, **_):
        return {
            "NatGateways": [
                {
                    "NatGatewayId": n["id"],
                    "VpcId": n["vpc_id"],
                    "SubnetId": n["subnet_id"],
                    "State": "available",
                    "NatGatewayAddresses": [
                        {
                            "NetworkInterfaceId": n["interface_ids"][0],
                            "PrivateIp": p,
                            "PublicIp": n["public_ips"][0],
                        }
                        for p in n["private_ips"]
                    ],
                }
                for n in self.d["nat_gateways"]
                if n["vpc_id"] in self._vpcs()
            ]
        }

    def describe_vpc_endpoints(self, **_):
        return {
            "VpcEndpoints": [
                {
                    "VpcEndpointId": e["id"],
                    "VpcId": e["vpc_id"],
                    "VpcEndpointType": e["type"],
                    "ServiceName": e["service_name"],
                    "SubnetIds": e["subnet_ids"],
                    "NetworkInterfaceIds": e["interface_ids"],
                    "PrivateDnsEnabled": e["private_dns"],
                    "State": "available",
                }
                for e in self.d["endpoints"]
                if e["vpc_id"] in self._vpcs()
            ]
        }

    def describe_managed_prefix_lists(self, **_):
        return {
            "PrefixLists": [
                {"PrefixListId": p["id"], "PrefixListName": p["name"]} for p in self.d["prefix_lists"]
            ]
        }

    def get_managed_prefix_list_entries(self, PrefixListId, **_):  # noqa: N803
        p = next(p for p in self.d["prefix_lists"] if p["id"] == PrefixListId)
        return {"Entries": [{"Cidr": c} for c in p["cidrs"]]}

    def describe_transit_gateway_attachments(self, **_):
        return {
            "TransitGatewayAttachments": [
                {
                    "TransitGatewayAttachmentId": a["id"],
                    "TransitGatewayId": a["transit_gateway_id"],
                    "ResourceId": a["vpc_id"],
                    "ResourceType": a["resource_type"],
                }
                for a in self.d["tgw_attachments"]
                if a["vpc_id"] in self._vpcs()
            ]
        }


class FakeSession:
    def __init__(self, doc: dict) -> None:
        self.doc = doc

    def client(self, name: str, region_name: str | None = None):
        if name == "ec2":
            return FakeEc2(self.doc, "123456789012", region_name or "eu-west-2")
        raise KeyError(name)
