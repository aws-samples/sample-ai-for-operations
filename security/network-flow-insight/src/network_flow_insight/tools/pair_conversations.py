# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: pair flow legs into client-to-server conversations.

Uses the aggregate's normalised ports: 0 means ephemeral, anything else is a service port. Exactly one
side with a service port makes that side the server. Both sides ephemeral, or both with service ports,
is ambiguous and is labelled, never guessed.
"""

from __future__ import annotations

from ._common import counted_rows, n, ok_rows

_KEY = ("client", "server", "port", "protocol", "path_class", "action")


def pair_conversations(rows: list[dict]) -> list[dict]:
    convs: dict[tuple, dict] = {}
    for r in ok_rows(counted_rows(rows)):
        src, dst = r["srcaddr"], r["dstaddr"]
        sp, dp = n(r.get("srcport")), n(r.get("dstport"))
        ambiguous = ""
        if sp == 0 and dp > 0:
            client, server, port, leg = src, dst, dp, "c2s"
        elif dp == 0 and sp > 0:
            client, server, port, leg = dst, src, sp, "s2c"
        else:
            ambiguous = "both ports ephemeral" if sp == 0 else "both ports are service ports"
            if protocol_without_ports(r):
                ambiguous = "protocol without ports"
            client, server = (src, dst) if src <= dst else (dst, src)
            leg = "c2s" if client == src else "s2c"
            port = max(sp, dp)
        key = (client, server, port, r.get("protocol"), r.get("path_class", "unknown"), r.get("action"))
        c = convs.setdefault(
            key,
            {
                "client": client,
                "server": server,
                "port": port,
                "protocol": r.get("protocol"),
                "path_class": r.get("path_class", "unknown"),
                "action": r.get("action"),
                "c2s_bytes": 0,
                "s2c_bytes": 0,
                "packets": 0,
                "records": 0,
                "first_day": r["day"],
                "last_day": r["day"],
                "ambiguous": bool(ambiguous),
                "ambiguity": ambiguous,
                "method": r.get("method"),
                "interface_ids": set(),
            },
        )
        c["c2s_bytes" if leg == "c2s" else "s2c_bytes"] += n(r.get("bytes"))
        c["packets"] += n(r.get("packets"))
        c["records"] += n(r.get("records"))
        c["first_day"] = min(c["first_day"], r["day"])
        c["last_day"] = max(c["last_day"], r["day"])
        c["interface_ids"].add(r.get("interface_id"))
        if ambiguous:  # ambiguous is an empty string (not ambiguous) or a reason; truthiness is intended  # nosemgrep: no-strings-as-booleans
            c["ambiguous"], c["ambiguity"] = True, ambiguous
    out = []
    for c in convs.values():
        c["total_bytes"] = c["c2s_bytes"] + c["s2c_bytes"]
        c["interface_ids"] = sorted(i for i in c["interface_ids"] if i)
        out.append(c)
    out.sort(key=lambda c: (-c["total_bytes"], c["client"], c["server"], c["port"], c["path_class"]))
    return out


def protocol_without_ports(r: dict) -> bool:
    return r.get("protocol") not in (6, 17)
