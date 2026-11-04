# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: attribute every aggregate row to a path class.

Authority, in order: the role of the interface the flow was logged on (and of the remote address's
owner), the subnet's route table, the ``traffic-path`` field. The method that decided each row is
recorded. Rows on forwarding interfaces re-observe traffic that a workload interface already counts,
so they carry ``counted = False`` and are used only by the gateway-specific tools.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from ..core.inventory import Inventory
from ..core.ipranges import is_private
from ._common import n
from .nat_scope import is_unsolicited, nat_leg, solicited_keys

PATH_CLASSES = (
    "internet-nat",
    "internet-igw",
    "gateway-endpoint",
    "interface-endpoint",
    "transit-gateway",
    "vpc-peering",
    "intra-vpc-same-az",
    "intra-vpc-cross-az",
    "cross-region",
    "vgw-dx",
    "via-vpc-resource",
    "internet-unresolved",
    "private-unresolved",
    "local-gateway",
    "unknown",
)
TRAFFIC_PATH_CODES = {
    1: "via-vpc-resource",
    2: "internet-igw",
    3: "vgw-dx",
    4: "vpc-peering",
    5: "cross-region",
    6: "local-gateway",
    7: "gateway-endpoint",
    8: "internet-igw",
}
ROUTE_TARGET_CLASS = {
    "nat-gateway": "internet-nat",
    "internet-gateway": "internet-igw",
    "gateway-endpoint": "gateway-endpoint",
    "transit-gateway": "transit-gateway",
    "peering": "vpc-peering",
    "vgw": "vgw-dx",
    "network-interface": "via-vpc-resource",
}


def classify_path(rows: list[dict], inventory: Inventory | None, *, inferred: bool = False) -> dict:
    """Return ``{"rows": [...], "methods": {...}, "traffic_path_crosscheck": {...}}``.

    ``inferred`` marks an inventory that was itself built from provider D heuristics, so every
    classification carries method ``inferred``.
    """
    out: list[dict] = []
    methods: Counter[str] = Counter()
    cross = Counter()
    disagreements: dict[tuple, dict] = defaultdict(lambda: {"records": 0, "bytes": 0})
    logged = {r["interface_id"] for r in rows if r.get("log_status", "OK") == "OK" and r.get("srcaddr") is not None}
    workload_ips = _workload_ips(inventory, logged)
    nat_addrs = inventory.nat_addresses() if inventory else set()
    nat_ifaces = set(inventory.nat_interface_ids()) if inventory else set()
    solicited = solicited_keys([r for r in rows if r.get("interface_id") in nat_ifaces], nat_addrs)
    for r in rows:
        c = dict(r)
        if r.get("log_status", "OK") != "OK" or r.get("srcaddr") is None:
            c.update(
                path_class="no-data",
                method="none",
                counted=False,
                direction=None,
                local_addr=None,
                remote_addr=None,
                role=None,
            )
        else:
            _classify_row(c, inventory, workload_ips, nat_addrs, inferred, solicited)
        methods[c["method"]] += n(c.get("records")) or 1
        if inventory and c.get("traffic_path") is not None and c.get("counted") and not inferred:
            tp = TRAFFIC_PATH_CODES.get(int(c["traffic_path"]))
            if tp and c["method"] != "traffic-path":
                ok = _compatible(tp, c["path_class"])
                cross["agree" if ok else "disagree"] += n(c.get("records")) or 1
                if not ok:
                    d = disagreements[(c["path_class"], tp, c.get("subnet_id") or "")]
                    d["records"] += n(c.get("records")) or 1
                    d["bytes"] += n(c.get("bytes"))
        out.append(c)
    return {
        "rows": out,
        "methods": dict(methods),
        "traffic_path_crosscheck": dict(cross),
        # Records whose own traffic-path contradicts the current inventory: a route changed during the window,
        # or the inventory is older or newer than the window. Their path class comes from the inventory.
        "traffic_path_disagreements": [
            {"path_class": k[0], "traffic_path_class": k[1], "subnet_id": k[2], **v}
            for k, v in sorted(disagreements.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))
        ],
    }


def _compatible(tp_class: str, path_class: str) -> bool:
    if tp_class == path_class:
        return True
    if tp_class == "via-vpc-resource":
        # AWS logs 1 for any path through another resource in the same VPC, another instance included.
        return path_class in (
            "intra-vpc-same-az",
            "intra-vpc-cross-az",
            "internet-nat",
            "interface-endpoint",
            "transit-gateway",
            "cross-region",
            "vpc-peering",
        )
    if tp_class == "internet-igw":
        return path_class in ("internet-igw", "gateway-endpoint")
    return False


def _workload_ips(inv: Inventory | None, logged: set[str] | None = None) -> set[str]:
    """Addresses of workload interfaces whose own records are in the data (``logged``: interface ids).

    Inbound from one of these is counted at the sender's egress. A workload that is in the inventory but logs
    nothing here (its VPC's flow log is not in this table) is not one of them, so its bytes are counted on arrival.
    """
    if not inv:
        return set()
    return {
        ip
        for i in inv.interfaces_by_role("workload")
        if logged is None or i["id"] in logged
        for ip in i.get("private_ips", [])
    }


def _classify_row(
    c: dict,
    inv: Inventory | None,
    workload_ips: set[str],
    nat_addrs: set[str],
    inferred: bool,
    solicited: set[tuple] | None = None,
) -> None:
    src, dst = c["srcaddr"], c["dstaddr"]
    iface = inv.interface(c["interface_id"]) if inv else None
    role = iface["role"] if iface else None
    ips = set(iface["private_ips"]) if iface else set()
    if src in ips:
        direction, local, remote = "out", src, dst
    elif dst in ips:
        direction, local, remote = "in", dst, src
    elif c.get("flow_direction") in ("egress", "ingress") and not iface:
        direction = "out" if c["flow_direction"] == "egress" else "in"
        local, remote = (src, dst) if direction == "out" else (dst, src)
    else:
        direction, local, remote = "transit", None, None
    c.update(direction=direction, local_addr=local, remote_addr=remote, role=role)
    c["remote_port"] = (
        (n(c.get("dstport")) if direction == "out" else n(c.get("srcport")))
        if direction != "transit"
        else None
    )
    if iface:
        for k, src_k in (("vpc_id", "vpc_id"), ("subnet_id", "subnet_id"), ("az_id", "az")):
            if not c.get(k) and iface.get(src_k):
                c[k] = iface[src_k]
    method_label = "inferred" if inferred else None

    if c.get("action") == "REJECT":
        c.update(path_class="rejected", method=method_label or "interface-role", counted=False)
        return
    if role == "nat-gateway":
        leg = nat_leg(c, nat_addrs)
        if leg == "translated" and is_unsolicited(c, nat_addrs, solicited or set()):
            leg = "unsolicited"
        c.update(
            path_class={
                "translated": "nat-translated-leg",
                "untranslated": "nat-untranslated-leg",
                "unsolicited": "nat-unsolicited-inbound",
            }.get(leg or "", "nat-unmatched"),
            method=method_label or "interface-role",
            counted=False,
        )
        return
    if role == "interface-endpoint":
        c.update(path_class="interface-endpoint", method=method_label or "interface-role", counted=False)
        return
    if role in ("transit-gateway", "load-balancer", "other"):
        c.update(path_class="forwarding-interface", method=method_label or "interface-role", counted=False)
        return

    # Workload interface (or unknown interface: classify on what the record itself says).
    if role == "workload":
        counted = direction == "out" or (direction == "in" and src not in workload_ips)
    else:
        # Interface not in the inventory (deleted since the window): count egress, and inbound from a public
        # source, which no other interface in the estate counts. Private inbound is counted at its sender.
        counted = direction == "out" or (direction == "in" and src is not None and not is_private(src))
    c["counted"] = counted
    if direction == "transit" or remote is None:
        c.update(path_class="unknown", method="none")
        return

    if inv and not iface:
        # The record carries its subnet (enhanced and full formats): classify from that subnet's route table.
        sub = inv.subnets.get(c.get("subnet_id") or "")
        if sub:
            iface = {
                "subnet_id": sub["id"],
                "vpc_id": sub.get("vpc_id"),
                "az": sub.get("az"),
                "region": sub.get("region"),
                "role": None,
                "private_ips": [],
            }
    if inv and iface:
        pc, m = _from_inventory(inv, iface, remote)
        if pc:
            c.update(path_class=pc, method=method_label or m)
            return
    tp = c.get("traffic_path")
    if tp is not None and int(tp) in TRAFFIC_PATH_CODES:
        pc = TRAFFIC_PATH_CODES[int(tp)]
        if pc == "via-vpc-resource" and not is_private(remote):
            c.update(
                path_class="internet-nat",
                method="traffic-path",
                path_note="via a resource in the VPC with a public remote; NAT assumed, confirm with inventory",
            )
        else:
            c.update(path_class=pc, method="traffic-path")
        return
    c.update(
        path_class="internet-unresolved" if not is_private(remote) else "private-unresolved",
        method="inferred" if inferred else "none",
    )


def _from_inventory(inv: Inventory, iface: dict, remote: str) -> tuple[str | None, str]:
    owner = inv.owner_of_ip(remote)
    if owner and owner["role"] == "interface-endpoint":
        return "interface-endpoint", "interface-role"
    remote_vpc = inv.vpc_for_ip(remote)
    if (
        remote_vpc
        and remote_vpc.get("region")
        and iface.get("region")
        and remote_vpc["region"] != iface["region"]
    ):
        return "cross-region", "route-table"
    if (
        owner
        and owner["role"] == "workload"
        and owner.get("vpc_id") == iface.get("vpc_id")
        and owner.get("az")
        and iface.get("az")
    ):
        return ("intra-vpc-same-az" if owner["az"] == iface["az"] else "intra-vpc-cross-az"), "interface-role"
    subnet = iface.get("subnet_id")
    if subnet:
        route = inv.route_for(subnet, remote)
        if route:
            tt = route["target_type"]
            if tt == "local":
                remote_subnet = inv.subnet_for_ip(remote)
                if remote_subnet and inv.subnets.get(subnet):
                    same = remote_subnet.get("az") == inv.subnets[subnet].get("az")
                    return ("intra-vpc-same-az" if same else "intra-vpc-cross-az"), "route-table"
                return "intra-vpc-same-az", "route-table"
            if tt in ROUTE_TARGET_CLASS:
                return ROUTE_TARGET_CLASS[tt], "route-table"
    return None, "none"
