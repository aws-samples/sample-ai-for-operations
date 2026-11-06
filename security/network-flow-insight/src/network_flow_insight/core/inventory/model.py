# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""The inventory document and its lookups.

All providers (A: EC2 in the current account, B: AWS Config aggregator, C: a JSON file produced by
``scripts/collect_inventory.py``) produce the same document. Schema (``schema_version`` 1)::

    {
      "schema_version": 1, "collected_at": "...", "source": "ec2|config|file",
      "vpcs":        [{"id", "account_id", "region", "cidrs": [..]}],
      "subnets":     [{"id", "vpc_id", "account_id", "region", "az", "cidr", "route_table_id"}],
      "route_tables":[{"id", "vpc_id", "routes": [{"destination"|"prefix_list_id",
                        "target_type", "target_id"}]}],
      "interfaces":  [{"id", "account_id", "region", "vpc_id", "subnet_id", "az", "role",
                        "private_ips": [..], "description"}],
      "nat_gateways":[{"id", "vpc_id", "subnet_id", "interface_ids": [..],
                        "private_ips": [..], "public_ips": [..]}],
      "endpoints":   [{"id", "vpc_id", "type": "Interface|Gateway", "service_name",
                        "subnet_ids": [..], "interface_ids": [..], "private_dns": bool}],
      "prefix_lists":[{"id", "name", "cidrs": [..]}],
      "tgw_attachments": [{"id", "transit_gateway_id", "vpc_id", "resource_type", "interface_ids": [..]}]
    }

``role`` is one of: ``workload``, ``nat-gateway``, ``interface-endpoint``, ``transit-gateway``,
``load-balancer``, ``other``. ``target_type`` is one of: ``local``, ``internet-gateway``,
``nat-gateway``, ``gateway-endpoint``, ``transit-gateway``, ``peering``, ``vgw``,
``network-interface``, ``other``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

SCHEMA_VERSION = 1
ROLES = ("workload", "nat-gateway", "interface-endpoint", "transit-gateway", "load-balancer", "other")
TARGETS = (
    "local",
    "internet-gateway",
    "nat-gateway",
    "gateway-endpoint",
    "transit-gateway",
    "peering",
    "vgw",
    "network-interface",
    "other",
)


class InventoryError(ValueError):
    pass


def validate_document(doc: dict[str, Any]) -> None:
    if not isinstance(doc, dict):
        raise InventoryError("inventory must be a JSON object")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise InventoryError(
            f"unsupported schema_version {doc.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )
    for key in ("vpcs", "subnets", "route_tables", "interfaces", "nat_gateways", "endpoints", "prefix_lists"):
        if not isinstance(doc.get(key, []), list):
            raise InventoryError(f"'{key}' must be a list")
    for i in doc.get("interfaces", []):
        if i.get("role") not in ROLES:
            raise InventoryError(f"interface {i.get('id')!r} has unknown role {i.get('role')!r}")
    for rt in doc.get("route_tables", []):
        for r in rt.get("routes", []):
            if r.get("target_type") not in TARGETS:
                raise InventoryError(
                    f"route table {rt.get('id')!r} has unknown target_type {r.get('target_type')!r}"
                )


def _net(c: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(c, strict=False)


class Inventory:
    def __init__(self, doc: dict[str, Any]) -> None:
        validate_document(doc)
        self.doc = doc
        self.source = doc.get("source", "file")
        self.collected_at = doc.get("collected_at", "")
        self.interfaces = {i["id"]: i for i in doc.get("interfaces", [])}
        self.subnets = {s["id"]: s for s in doc.get("subnets", [])}
        self.vpcs = {v["id"]: v for v in doc.get("vpcs", [])}
        self.route_tables = {r["id"]: r for r in doc.get("route_tables", [])}
        self.nat_gateways = {n["id"]: n for n in doc.get("nat_gateways", [])}
        self.endpoints = list(doc.get("endpoints", []))
        self.prefix_lists = {p["id"]: p for p in doc.get("prefix_lists", [])}
        self._ip_owner: dict[str, str] = {}
        for i in self.interfaces.values():
            for ip in i.get("private_ips", []):
                self._ip_owner[ip] = i["id"]
        self._subnet_nets = sorted(
            ((_net(s["cidr"]), s["id"]) for s in self.subnets.values() if s.get("cidr")),
            key=lambda t: t[0].prefixlen,
            reverse=True,
        )
        self._vpc_nets = sorted(
            ((_net(c), v["id"]) for v in self.vpcs.values() for c in v.get("cidrs", [])),
            key=lambda t: t[0].prefixlen,
            reverse=True,
        )
        self._pl_nets = {pid: [_net(c) for c in p.get("cidrs", [])] for pid, p in self.prefix_lists.items()}
        self._main_rt = {rt["vpc_id"]: rt["id"] for rt in doc.get("route_tables", []) if rt.get("main")}

    # -- interfaces and addresses ------------------------------------------------------------
    def role(self, interface_id: str) -> str | None:
        i = self.interfaces.get(interface_id)
        return i["role"] if i else None

    def interface(self, interface_id: str) -> dict | None:
        return self.interfaces.get(interface_id)

    def interface_ips(self, interface_id: str) -> set[str]:
        i = self.interfaces.get(interface_id)
        return set(i.get("private_ips", [])) if i else set()

    def owner_of_ip(self, ip: str) -> dict | None:
        iid = self._ip_owner.get(ip)
        return self.interfaces.get(iid) if iid else None

    def interfaces_by_role(self, role: str) -> list[dict]:
        return [i for i in self.interfaces.values() if i["role"] == role]

    def nat_interface_ids(self) -> list[str]:
        ids = {i["id"] for i in self.interfaces_by_role("nat-gateway")}
        for n in self.nat_gateways.values():
            ids.update(n.get("interface_ids", []))
        return sorted(ids)

    def nat_addresses(self, nat_id: str | None = None) -> set[str]:
        """Every private address of the gateway(s), secondary addresses included."""
        out: set[str] = set()
        for n in self.nat_gateways.values():
            if nat_id and n["id"] != nat_id:
                continue
            out.update(n.get("private_ips", []))
            for iid in n.get("interface_ids", []):
                out.update(self.interface_ips(iid))
        if nat_id is None:
            for i in self.interfaces_by_role("nat-gateway"):
                out.update(i.get("private_ips", []))
        return out

    def nat_for_interface(self, interface_id: str) -> str | None:
        for n in self.nat_gateways.values():
            if interface_id in n.get("interface_ids", []):
                return n["id"]
        return None

    # -- networks ------------------------------------------------------------------------------
    def vpc_for_ip(self, ip: str) -> dict | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, vid in self._vpc_nets:
            if a in net:
                return self.vpcs[vid]
        return None

    def subnet_for_ip(self, ip: str) -> dict | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, sid in self._subnet_nets:
            if a in net:
                return self.subnets[sid]
        return None

    def vpc_cidrs(self) -> list[str]:
        return [c for v in self.vpcs.values() for c in v.get("cidrs", [])]

    # -- routing -------------------------------------------------------------------------------
    def route_table_for_subnet(self, subnet_id: str) -> dict | None:
        s = self.subnets.get(subnet_id)
        if not s:
            return None
        rt = self.route_tables.get(s.get("route_table_id") or "")
        if rt:
            return rt
        return self.route_tables.get(self._main_rt.get(s.get("vpc_id"), ""))

    def route_for(self, subnet_id: str, dst_ip: str) -> dict | None:
        """Longest-prefix route in the subnet's route table for ``dst_ip``."""
        rt = self.route_table_for_subnet(subnet_id)
        if not rt:
            return None
        try:
            a = ipaddress.ip_address(dst_ip)
        except ValueError:
            return None
        best: tuple[int, dict] | None = None
        for r in rt.get("routes", []):
            nets: list[Any] = []
            if r.get("destination"):
                nets = [_net(r["destination"])]
            elif r.get("prefix_list_id"):
                nets = self._pl_nets.get(r["prefix_list_id"], [])
            for n in nets:
                if a.version == n.version and a in n and (best is None or n.prefixlen > best[0]):
                    best = (n.prefixlen, r)
        return best[1] if best else None

    def subnets_routing_to(self, target_type: str, ip: str) -> list[dict]:
        """Subnets whose route for ``ip`` has the given target type."""
        return [
            s
            for s in self.subnets.values()
            if (r := self.route_for(s["id"], ip)) and r["target_type"] == target_type
        ]

    def gateway_endpoint_prefixlists(self) -> dict[str, str]:
        """Prefix-list id -> service name for gateway endpoints (``s3``, ``dynamodb``)."""
        out = {}
        for e in self.endpoints:
            if e.get("type") == "Gateway":
                for rt in self.route_tables.values():
                    for r in rt.get("routes", []):
                        if r.get("target_id") == e["id"] and r.get("prefix_list_id"):
                            out[r["prefix_list_id"]] = e["service_name"].rsplit(".", 1)[-1]
        return out
