# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: NAT-scoped traffic.

NAT traffic is measured on the gateway's own interfaces. A NAT gateway's private address is the source or
destination of every record its interface logs, on both legs:

- workload side, out: workload -> NAT (``pkt-dstaddr`` is the real remote)
- internet side, out: NAT -> remote (``pkt-srcaddr`` is the NAT address)
- internet side, return: remote -> NAT (``pkt-dstaddr`` is the NAT address)
- workload side, return: NAT -> workload (``pkt-srcaddr`` is the real remote)

The translated leg is the internet side: the packet's own address on the NAT side is the NAT address. The
untranslated leg is the workload side: the packet still carries the real remote in ``pkt-*``. Without
``pkt-*`` fields, the leg is told by the other address: private means workload side. Counting the
translated leg only means each byte is counted once; the untranslated leg feeds the leg check and names
the workloads. Records on a NAT interface with no known NAT address are unmatched: a NAT address is missing
from the filter. Internet-side inbound that matches no translated outbound (remote, remote port, protocol)
is unsolicited, an internet scan of the NAT address for example: the gateway never translates or forwards
it and its own metrics leave it out, so it is reported apart and kept out of every total.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..core.ipranges import is_private
from ._common import n


def nat_leg(row: dict, nat_addresses: set[str]) -> str | None:
    """``"translated"``, ``"untranslated"`` or ``None`` (neither address is a NAT address)."""
    src, dst = row.get("srcaddr"), row.get("dstaddr")
    if src in nat_addresses:
        side_pkt, peer = row.get("pkt_srcaddr"), dst
    elif dst in nat_addresses:
        side_pkt, peer = row.get("pkt_dstaddr"), src
    else:
        return None
    if side_pkt:
        return "translated" if side_pkt in nat_addresses else "untranslated"
    return "untranslated" if peer and is_private(peer) and peer not in nat_addresses else "translated"


_PRIVATE_RE = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)"


def translated_leg_sql(quoted_addresses: str, pkt_fields: bool) -> str:
    """SQL predicate for the translated leg, ``quoted_addresses`` being ``'a', 'b'`` (already quoted)."""
    a = quoted_addresses
    if pkt_fields:
        return f"((srcaddr IN ({a}) AND pkt_srcaddr IN ({a})) OR (dstaddr IN ({a}) AND pkt_dstaddr IN ({a})))"
    return (
        f"((srcaddr IN ({a}) AND NOT regexp_like(dstaddr, '{_PRIVATE_RE}'))"
        f" OR (dstaddr IN ({a}) AND NOT regexp_like(srcaddr, '{_PRIVATE_RE}')))"
    )


def _block() -> dict:
    return {"total_bytes": 0, "out_bytes": 0, "in_bytes": 0, "records": 0}


def _ekey(r: dict, remote: str, remote_port: Any) -> tuple:
    return (r.get("interface_id"), remote, n(remote_port), str(r.get("protocol")))


def solicited_keys(rows: list[dict], nat_addresses: set[str]) -> set[tuple]:
    """``(interface, remote, remote port, protocol)`` of every translated outbound record.

    An inbound translated record is a return only if its remote, remote port and protocol were sent to from the
    same NAT interface; anything else reached the NAT address unsolicited (an internet scan, say). The remote's
    port survives the aggregate's port normalisation on both legs, so this works on aggregate rows.
    """
    out: set[tuple] = set()
    for r in rows:
        if r.get("action") == "ACCEPT" and r.get("srcaddr") in nat_addresses and nat_leg(r, nat_addresses) == "translated":
            out.add(_ekey(r, r.get("dstaddr"), r.get("dstport")))
    return out


def is_unsolicited(r: dict, nat_addresses: set[str], solicited: set[tuple]) -> bool:
    """A translated inbound record (remote -> NAT address) with no matching translated outbound record."""
    return (
        r.get("dstaddr") in nat_addresses
        and r.get("srcaddr") not in nat_addresses
        and _ekey(r, r.get("srcaddr"), r.get("srcport")) not in solicited
    )


def nat_scope(rows: list[dict], nat_addresses: list[str], nat_interface_ids: list[str]) -> dict:
    nat = set(nat_addresses)
    ifaces = set(nat_interface_ids)
    trans, untrans, unmatched, unsolicited = _block(), _block(), _block(), _block()
    unsolicited_src: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "records": 0})
    solicited = solicited_keys([r for r in rows if r.get("interface_id") in set(nat_interface_ids)], nat)
    unscoped = 0
    by_iface: dict[str, dict] = defaultdict(
        lambda: {"translated_bytes": 0, "untranslated_bytes": 0, "unmatched_bytes": 0, "records": 0}
    )
    remote: dict[tuple, dict] = defaultdict(lambda: {"bytes": 0, "packets": 0, "records": 0})
    by_day: dict[str, int] = defaultdict(int)
    by_nat_addr: dict[str, int] = defaultdict(int)
    wl: dict[str, dict] = defaultdict(lambda: {"out_bytes": 0, "in_bytes": 0})
    wl_remote: dict[tuple[str, str], dict] = defaultdict(lambda: {"out_bytes": 0, "in_bytes": 0})
    pkt_fields = False
    for r in rows:
        if r.get("interface_id") not in ifaces or r.get("srcaddr") is None or r.get("action") != "ACCEPT":
            continue
        pkt_fields = pkt_fields or bool(r.get("pkt_srcaddr"))
        b = n(r.get("bytes"))
        recs = n(r.get("records"))
        unscoped += b
        src, dst = r["srcaddr"], r["dstaddr"]
        iface = by_iface[r["interface_id"]]
        iface["records"] += recs
        leg = nat_leg(r, nat)
        if leg is None:
            unmatched["total_bytes"] += b
            unmatched["records"] += recs
            iface["unmatched_bytes"] += b
            continue
        if leg == "translated" and is_unsolicited(r, nat, solicited):
            unsolicited["total_bytes"] += b
            unsolicited["in_bytes"] += b
            unsolicited["records"] += recs
            iface["unsolicited_bytes"] = iface.get("unsolicited_bytes", 0) + b
            unsolicited_src[src]["bytes"] += b
            unsolicited_src[src]["records"] += recs
            continue
        if leg == "translated":
            out = src in nat
            rem, rport = (dst, n(r.get("dstport"))) if out else (src, n(r.get("srcport")))
            trans["total_bytes"] += b
            trans["out_bytes" if out else "in_bytes"] += b
            trans["records"] += recs
            iface["translated_bytes"] += b
            k = (rem, rport, r.get("protocol"), "out" if out else "in")
            remote[k]["bytes"] += b
            remote[k]["packets"] += n(r.get("packets"))
            remote[k]["records"] += recs
            by_day[r["day"]] += b
            by_nat_addr[src if out else dst] += b
            continue
        # Untranslated (workload side): the workload is the non-NAT record address.
        out = dst in nat
        workload = src if out else dst
        real_remote = r.get("pkt_dstaddr") if out else r.get("pkt_srcaddr")
        key = "out_bytes" if out else "in_bytes"
        untrans["total_bytes"] += b
        untrans[key] += b
        untrans["records"] += recs
        iface["untranslated_bytes"] += b
        wl[workload][key] += b
        if real_remote and real_remote not in nat:
            wl_remote[(workload, real_remote)][key] += b

    def total(v: dict) -> int:
        return v["out_bytes"] + v["in_bytes"]

    return {
        "nat_addresses": sorted(nat),
        "nat_interfaces": sorted(ifaces),
        "translated": trans,
        "untranslated": untrans,
        "unmatched": unmatched,
        # Accepted on the internet side but never translated or forwarded: not NAT traffic, not in any total.
        "unsolicited": {
            **unsolicited,
            "sources": len(unsolicited_src),
            "top_sources": [
                {"remote": k, **v}
                for k, v in sorted(unsolicited_src.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))[:10]
            ],
        },
        "unscoped_interface_total_bytes": unscoped,
        "by_interface": {k: dict(v) for k, v in sorted(by_iface.items())},
        "by_nat_address": dict(sorted(by_nat_addr.items())),
        "by_day": dict(sorted(by_day.items())),
        "remote_rows": [
            {"remote": k[0], "remote_port": k[1], "protocol": k[2], "direction": k[3], **v}
            for k, v in sorted(remote.items(), key=lambda kv: (-kv[1]["bytes"], str(kv[0])))
        ],
        "by_workload": [
            {"workload": ip, **v, "total_bytes": total(v)}
            for ip, v in sorted(wl.items(), key=lambda kv: (-total(kv[1]), kv[0]))
        ],
        "by_workload_remote": [
            {"workload": k[0], "remote": k[1], **v, "total_bytes": total(v)}
            for k, v in sorted(wl_remote.items(), key=lambda kv: (-total(kv[1]), kv[0]))
        ],
        "attribution_method": "untranslated-leg",
        "pkt_fields": pkt_fields,
        "leg_rule": "pkt-srcaddr/pkt-dstaddr on the NAT side" if pkt_fields else "other address private or public",
    }
