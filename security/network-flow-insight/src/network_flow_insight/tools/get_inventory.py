# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Data retrieval tool: network inventory from provider A (EC2), B (Config aggregator) or C (file)."""

from __future__ import annotations

from typing import Any

from ..core.inventory import Inventory, load_provider

PROVIDER_OPTIONS = {
    "A": "Amazon EC2 in the current account (ec2:Describe*, ec2:GetManagedPrefixListEntries)",
    "B": "AWS Config aggregator reachable from here",
    "C": "inventory JSON file; scripts/collect_inventory.py produces it",
    "D": "none: forwarding interfaces are inferred from the data and labelled inferred",
}


def get_inventory(
    provider: str = "auto",
    *,
    session: Any = None,
    region: str = "",
    regions: list[str] | None = None,
    inventory_file: str = "",
    aggregator: str = "",
) -> tuple[str, Inventory | None, dict]:
    letter, inv, note = load_provider(
        provider,
        session=session,
        region=region,
        regions=regions,
        inventory_file=inventory_file,
        aggregator=aggregator,
    )
    summary: dict = {"provider": letter, "note": note, "available": inv is not None}
    if inv:
        summary.update(
            source=inv.source,
            collected_at=inv.collected_at,
            vpcs=len(inv.vpcs),
            subnets=len(inv.subnets),
            interfaces=len(inv.interfaces),
            nat_gateways=sorted(inv.nat_gateways),
            endpoints=len(inv.endpoints),
            route_tables=len(inv.route_tables),
        )
    else:
        summary["options"] = PROVIDER_OPTIONS
    return letter, inv, summary
