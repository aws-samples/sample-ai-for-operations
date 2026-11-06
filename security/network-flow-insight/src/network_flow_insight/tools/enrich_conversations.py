# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: attach consumer and provider identities to conversations.

The consumer is the client's subnet (inventory) or its /24. The provider is the destination bucket
with its service or network name, or the /24 for unnamed internet and AWS-hosted addresses. These are
the keys the intent baseline, drift and what-if all share.
"""

from __future__ import annotations

from ..core.intent_schema import Intent
from ..core.inventory import Inventory
from ..core.ipranges import is_private
from ._common import net24
from .classify_destination import bucket_for


def provider_key(dest: dict, server: str) -> tuple[str, str]:
    b = dest["bucket"]
    if b == "aws-service":
        return b, dest["service"]
    if b in ("named-network", "own-vpc", "prefix-list"):
        return b, dest["name"]
    return b, net24(server)


def provider_endpoint(dest: dict, server: str) -> dict:
    b, k = provider_key(dest, server)
    if b == "aws-service":
        return {"bucket": b, "service": k}
    if b in ("named-network", "own-vpc", "prefix-list"):
        return {"bucket": b, "network": k}
    return {"bucket": b, "cidr": k}


def enrich_conversations(
    convs: list[dict], dest_map: dict[str, dict], inventory: Inventory | None, intent: Intent | None = None
) -> list[dict]:
    out = []
    for c in convs:
        e = dict(c)
        client, server = c["client"], c["server"]
        subnet = inventory.subnet_for_ip(client) if inventory else None
        vpc = inventory.vpc_for_ip(client) if inventory else None
        e["client_subnet"] = subnet["id"] if subnet else None
        e["client_vpc"] = vpc["id"] if vpc else None
        e["consumer"] = subnet["id"] if subnet else net24(client)
        e["egress"] = bool(vpc) or is_private(client)
        dest = dest_map.get(server) or {
            "bucket": "other-internet",
            "service": "",
            "name": "",
            "region": "",
            "cross_region": False,
        }
        e["dest_bucket"] = dest["bucket"]
        e["dest_service"] = dest["service"]
        e["dest_name"] = dest["name"]
        e["dest_region"] = dest["region"]
        e["dest_cross_region"] = dest["cross_region"]
        e["dest_method"] = dest["method"] if "method" in dest else ""
        e["provider"] = list(provider_key(dest, server))
        custom = bucket_for(dest, c["path_class"], intent)
        e["customer_bucket"] = custom["bucket"]
        e["disposition"] = custom["disposition"]
        out.append(e)
    return out
