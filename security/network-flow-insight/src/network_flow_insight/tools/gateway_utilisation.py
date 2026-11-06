# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: bytes per NAT gateway in the window, with idle and near-idle gateways named."""

from __future__ import annotations

from ..core.inventory import Inventory


def gateway_utilisation(nat: dict, inventory: Inventory | None, idle_threshold_bytes: int) -> dict:
    """``nat`` is the output of ``nat_scope``."""
    per_iface = nat["by_interface"]
    gateways: dict[str, dict] = {}
    if inventory:
        for gid, g in sorted(inventory.nat_gateways.items()):
            t = sum(per_iface.get(i, {}).get("translated_bytes", 0) for i in g.get("interface_ids", []))
            seen = any(i in per_iface for i in g.get("interface_ids", []))
            gateways[gid] = {
                "gateway_id": gid,
                "vpc_id": g.get("vpc_id"),
                "translated_bytes": t,
                "interfaces": g.get("interface_ids", []),
                "seen_in_flow_logs": seen,
            }
    else:
        for iface, v in sorted(per_iface.items()):
            gateways[iface] = {
                "gateway_id": iface,
                "vpc_id": None,
                "translated_bytes": v["translated_bytes"],
                "interfaces": [iface],
                "seen_in_flow_logs": True,
                "inferred": True,
            }
    for g in gateways.values():
        if not g["seen_in_flow_logs"]:
            g["status"] = "no-flow-log"
        elif g["translated_bytes"] == 0:
            g["status"] = "idle"
        elif g["translated_bytes"] < idle_threshold_bytes:
            g["status"] = "near-idle"
        else:
            g["status"] = "active"
    rows = sorted(gateways.values(), key=lambda g: (-g["translated_bytes"], g["gateway_id"]))
    return {
        "gateways": rows,
        "idle_threshold_bytes": idle_threshold_bytes,
        "idle_or_near_idle": [g["gateway_id"] for g in rows if g["status"] in ("idle", "near-idle")],
        "without_flow_log": [g["gateway_id"] for g in rows if g["status"] == "no-flow-log"],
        "total_translated_bytes": sum(g["translated_bytes"] for g in rows),
    }
