# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Precision tool: provider D, inventory-free heuristics.

A NAT gateway interface's own private address is on every record it logs: public remotes on the
internet-side leg, private workloads on the workload-side leg, with the bytes of the two legs in balance;
``pkt-*`` fields on the workload leg carry the real remote, which confirms it. Any other interface that logs
records in which neither address is its own is a forwarding interface: a Transit Gateway attachment or an
appliance sees private addresses on both sides. Every conclusion carries a confidence and the evidence, and
is labelled ``inferred``.
"""

from __future__ import annotations

from collections import defaultdict

from ..core.ipranges import is_private
from ._common import n, ok_rows
from .nat_scope import nat_leg


def detect_forwarding_interfaces(
    rows: list[dict],
    *,
    foreign_share_threshold: float = 0.30,
    nat_coverage_ratio: float = 0.80,
    leg_balance_tolerance: float = 0.15,
) -> dict:
    by_iface: dict[str, list[dict]] = defaultdict(list)
    for r in ok_rows(rows):
        by_iface[r["interface_id"]].append(r)
    # Pass 1: every address each interface's records mention, and its main addresses (on most of its records).
    recorded: dict[str, set[str]] = {}
    main: dict[str, set[str]] = {}
    for iface, rs in by_iface.items():
        w: dict[str, int] = defaultdict(int)
        for r in rs:
            for a in {r["srcaddr"], r["dstaddr"]}:
                w[a] += n(r.get("records")) or 1
        recorded[iface] = set(w)
        floor = (1 - foreign_share_threshold) * sum(n(r.get("records")) or 1 for r in rs)
        main[iface] = {a for a, x in w.items() if x >= floor}
    main_on: dict[str, set[str]] = defaultdict(set)  # address -> interfaces it is a main address of
    for iface, addrs in main.items():
        for a in addrs:
            main_on[a].add(iface)
    result: dict[str, dict] = {}
    for iface, rs in sorted(by_iface.items()):
        weight: dict[str, int] = defaultdict(int)
        total = 0
        for r in rs:
            w = n(r.get("records")) or 1
            total += w
            for a in {r["srcaddr"], r["dstaddr"]}:
                weight[a] += w
        dominant, dom_w = max(weight.items(), key=lambda kv: (kv[1], kv[0]))
        foreign = round(1 - dom_w / total, 4) if total else 0.0
        entry = {
            "interface_id": iface,
            "dominant_address": dominant,
            "foreign_share": foreign,
            "records": total,
            "method": "inferred",
            "confirm_with": f"aws ec2 describe-network-interfaces --network-interface-ids {iface}",
        }
        nat = _nat_signature(rs, weight, total, 1 - foreign_share_threshold, leg_balance_tolerance)
        if nat:
            entry.update(role_guess="nat-gateway", **nat)
            result[iface] = entry
            continue
        # A Transit Gateway attachment (or an appliance) also puts its own address on every record, but pkt-*
        # carries the real peer on the attachment's side. Without pkt-* fields it cannot be told from a workload.
        relayed, relay_addr = None, dominant
        for a, w in weight.items():
            if a and w >= (1 - foreign_share_threshold) * total:
                share = _relayed_share(rs, a)
                if share is not None and (relayed is None or share > relayed):
                    relayed, relay_addr = share, a
        if relayed is not None and relayed >= 0.5:
            dominant, dom_w = relay_addr, weight[relay_addr]
            all_private = all(is_private(r["srcaddr"]) and is_private(r["dstaddr"]) for r in rs)
            entry.update(
                role_guess="transit-gateway-or-appliance" if all_private else "forwarding-unknown",
                confidence="high" if all_private else "medium",
                owned_addresses=[],
                evidence=(
                    f"{dominant} is on {round(dom_w / total * 100, 1)}% of records but pkt-* names another address "
                    f"on its side on {round(relayed * 100, 1)}% of them: it relays traffic for others"
                ),
            )
            result[iface] = entry
            continue
        # Without pkt-*: a relay's address is never recorded by the logged workloads it talks to (they record
        # the real peer). A server's address is recorded by its clients' own interfaces.
        ghost: list[str] = []
        if relayed is None:
            for a in sorted(main[iface]):
                ghost = _ghost_peers(rs, a, iface, recorded, main_on)
                if ghost:
                    dominant, dom_w = a, weight[a]
                    break
        if ghost:
            entry.update(
                role_guess="transit-gateway-or-appliance",
                confidence="medium",
                owned_addresses=[],
                evidence=(
                    f"{dominant} is on {round(dom_w / total * 100, 1)}% of records, all private, but the "
                    f"{len(ghost)} logged workload(s) it exchanges traffic with ({', '.join(ghost[:3])}) never record "
                    "that address on their own interfaces: it relays traffic for others (no pkt-* fields to confirm)"
                ),
            )
            result[iface] = entry
            continue
        if foreign < foreign_share_threshold:
            entry.update(
                role_guess="workload",
                confidence="high" if foreign < 0.05 else "medium",
                owned_addresses=[dominant],
                evidence=f"{dominant} is on {round(dom_w / total * 100, 1)}% of records",
            )
            result[iface] = entry
            continue
        # Forwarding interface without a NAT signature: Transit Gateway attachment, appliance or unknown.
        private_pairs = sum(
            n(r.get("records")) or 1 for r in rs if is_private(r["srcaddr"]) and is_private(r["dstaddr"])
        )
        priv_share = private_pairs / total if total else 0
        entry.update(
            role_guess="transit-gateway-or-appliance" if priv_share >= 0.5 else "forwarding-unknown",
            confidence="medium" if priv_share >= 0.8 else "low",
            owned_addresses=[],
            evidence=f"{round(priv_share * 100, 1)}% of records are private-to-private through this interface",
        )
        result[iface] = entry
    return {
        "interfaces": result,
        "provider": "D",
        "note": "all roles are inferred from traffic shape; confirm with the command shown for each interface",
    }


def _ghost_peers(
    rs: list[dict], address: str, iface: str, recorded: dict[str, set[str]], main_on: dict[str, set[str]]
) -> list[str]:
    """Logged peers that ``address`` exchanges traffic with but whose own interfaces never record ``address``.

    A peer is logged when it is a main address of another interface. Returns the peers only if there is at least
    one, none of their interfaces records ``address``, and every record on ``iface`` is private to private.
    """
    if not is_private(address) or not all(is_private(r["srcaddr"]) and is_private(r["dstaddr"]) for r in rs):
        return []
    peers = {r["dstaddr"] if r["srcaddr"] == address else r["srcaddr"] for r in rs if address in (r["srcaddr"], r["dstaddr"])}
    logged = {p: main_on[p] - {iface} for p in peers if main_on.get(p, set()) - {iface}}
    if not logged or any(address in recorded[y] for ys in logged.values() for y in ys):
        return []
    return sorted(logged)


def _relayed_share(rs: list[dict], address: str) -> float | None:
    """Share of records where ``address`` is in the record but pkt-* names a different address on its side.

    ``None`` when the records carry no pkt-* fields.
    """
    seen = relayed = 0
    for r in rs:
        if r["srcaddr"] == address:
            side = r.get("pkt_srcaddr")
        elif r["dstaddr"] == address:
            side = r.get("pkt_dstaddr")
        else:
            continue
        if not side:
            continue
        w = n(r.get("records")) or 1
        seen += w
        relayed += w if side != address else 0
    return relayed / seen if seen else None


def _nat_signature(
    rs: list[dict], weight: dict[str, int], total: int, min_cover: float, tolerance: float
) -> dict | None:
    """NAT gateway test: private addresses on most records, public remotes on one leg, private peers on the
    other, bytes balanced between the legs overall and per (protocol, service port). ``pkt-*`` showing the
    real remote on the workload leg confirms it.
    """
    cands: list[tuple[str, float, int, int, int]] = []
    idx: dict[str, list[dict]] = defaultdict(list)
    for r in rs:
        for a in {r["srcaddr"], r["dstaddr"]}:
            idx[a].append(r)
    # Only addresses on a meaningful share of records can be the interface's own NAT addresses.
    floor = 0.05 * total
    for a in sorted(x for x, w in weight.items() if x and w >= floor and is_private(x)):
        mine = idx[a]
        public, private = set(), set()
        t = u = pkt_evidence = 0
        # Per (protocol, service port): the internet leg shows the remote's port, the workload leg shows the
        # NAT address's own port (it stands in for the remote). A NAT mirrors every flow, port for port.
        pub_port: dict[tuple, int] = defaultdict(int)
        priv_port: dict[tuple, int] = defaultdict(int)
        for r in mine:
            a_is_src = r["srcaddr"] == a
            other = r["dstaddr"] if a_is_src else r["srcaddr"]
            b = n(r.get("bytes"))
            if is_private(other):
                private.add(other)
                priv_port[(r.get("protocol"), n(r.get("srcport") if a_is_src else r.get("dstport")))] += b
            else:
                public.add(other)
                pub_port[(r.get("protocol"), n(r.get("dstport") if a_is_src else r.get("srcport")))] += b
            leg = nat_leg(r, {a})
            t += b if leg == "translated" else 0
            u += b if leg == "untranslated" else 0
            side_pkt = r.get("pkt_srcaddr") if a_is_src else r.get("pkt_dstaddr")
            pkt_evidence += 1 if (side_pkt and side_pkt != a) else 0
        has_pkt = any(r.get("pkt_srcaddr") for r in mine)
        if len(public) < 2 or not private or not u or (has_pkt and not pkt_evidence):
            continue
        keys = set(pub_port) | set(priv_port)
        span = sum(pub_port[k] + priv_port[k] for k in keys)
        mismatch = sum(abs(pub_port[k] - priv_port[k]) for k in keys) / span if span else 1.0
        balance = t / u
        if abs(balance - 1) <= tolerance and mismatch <= tolerance:
            cands.append((a, balance, len(public), len(private), pkt_evidence))
    if not cands:
        return None
    names = {c[0] for c in cands}
    covered = sum(n(r.get("records")) or 1 for r in rs if r["srcaddr"] in names or r["dstaddr"] in names)
    if not total or covered / total < min_cover:
        return None
    pkt = sum(c[4] for c in cands)
    balance = round(sum(c[1] for c in cands) / len(cands), 4)
    return {
        "confidence": "high" if pkt else "medium",
        "nat_addresses_guess": sorted(names),
        "owned_addresses": sorted(names),
        "translated_to_untranslated": balance,
        "evidence": (
            f"{len(names)} private address(es) on {round(covered / total * 100, 1)}% of records, reaching "
            f"{max(c[2] for c in cands)} public remotes on one leg and {max(c[3] for c in cands)} private "
            f"peers on the other; leg bytes balanced ({balance})"
            + (f"; {pkt} records carry the real remote in pkt-* fields" if pkt else "; no pkt-* fields to confirm")
        ),
    }


def inferred_inventory_document(
    detection: dict, flow_regions: dict[str, tuple[str, str]] | None = None
) -> dict:
    """A minimal inventory document built from detection, so downstream tools share one code path.

    ``flow_regions`` maps interface id to ``(account_id, region)`` when known from the aggregate.
    """
    role_map = {
        "workload": "workload",
        "nat-gateway": "nat-gateway",
        "transit-gateway-or-appliance": "transit-gateway",
    }
    interfaces = []
    for iface, d in detection["interfaces"].items():
        acct, region = (flow_regions or {}).get(iface, ("", ""))
        interfaces.append(
            {
                "id": iface,
                "account_id": acct,
                "region": region,
                "vpc_id": "",
                "subnet_id": "",
                "az": "",
                "role": role_map.get(d["role_guess"], "other"),
                "private_ips": list(d.get("owned_addresses", [])),
                "description": "inferred",
                "inferred": True,
            }
        )
    return {
        "schema_version": 1,
        "source": "inferred",
        "collected_at": "",
        "vpcs": [],
        "subnets": [],
        "route_tables": [],
        "interfaces": interfaces,
        "nat_gateways": [],
        "endpoints": [],
        "prefix_lists": [],
        "tgw_attachments": [],
    }
