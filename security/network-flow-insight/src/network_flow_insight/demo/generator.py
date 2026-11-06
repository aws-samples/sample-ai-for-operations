# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Deterministic generator for the synthetic estate.

``generate(out_dir, tier, seed)`` writes, under ``out_dir``:

* ``s3/AWSLogs/<account>/vpcflowlogs/<region>/yyyy/mm/dd/*.log.gz`` flow logs in the standard layout,
  with the field set of the chosen tier;
* ``inventory.json`` (provider C schema), ``ip-ranges.json``, ``prices.json``, ``intent.yaml``,
  ``resolver.json``, ``metrics.json`` and ``cur.json``;
* ``ground_truth.json``: totals computed directly from the traffic templates, independent of every
  analysis tool, which the evaluations compare against to the byte.

The same seed always produces byte-identical output.
"""

from __future__ import annotations

import gzip
import json
import random
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ..core.ipranges import IpRanges
from ..core.tablescheme import DEFAULT_FIELDS, ENHANCED_FIELDS, FULL_FIELDS
from . import estate as E

TIERS = ("basic", "enhanced", "full")
TIER_FIELDS = {
    "basic": DEFAULT_FIELDS,
    "enhanced": DEFAULT_FIELDS + ENHANCED_FIELDS,
    "full": DEFAULT_FIELDS + FULL_FIELDS,
}
PATH_BY_KIND = {
    "nat": "internet-nat",
    "gateway-endpoint": "gateway-endpoint",
    "interface-endpoint": "interface-endpoint",
    "transit-gateway": "transit-gateway",
    "cross-region": "cross-region",
    "vgw": "vgw-dx",
    "internet-gateway": "internet-igw",
}
TRAFFIC_PATH_CODE = {
    "gateway-endpoint": 7,
    "internet-gateway": 8,
    "vgw": 3,
    "nat": 1,
    "interface-endpoint": 1,
    "transit-gateway": 1,
    "cross-region": 1,
    "intra-vpc": 1,  # AWS logs 1 ("another resource in the same VPC") on instance-to-instance egress too
}
# server address -> (destination bucket, service)
EXPECTED_DEST = {
    E.INTERNET["a"]: ("other-internet", ""),
    E.INTERNET["b"]: ("other-internet", ""),
    E.INTERNET["new"]: ("other-internet", ""),
    E.INTERNET["c"]: ("other-internet", ""),
    E.INTERNET["gone"]: ("other-internet", ""),
    E.S3_LOCAL[0]: ("aws-service", "S3"),
    E.S3_LOCAL[1]: ("aws-service", "S3"),
    E.S3_LOCAL[2]: ("aws-service", "S3"),
    E.S3_REMOTE_REGION: ("aws-service", "S3"),
    E.DDB_PUBLIC[0]: ("aws-service", "DYNAMODB"),
    E.DDB_PUBLIC[1]: ("aws-service", "DYNAMODB"),
    "10.10.1.200": ("aws-service", "DYNAMODB"),
    E.EC2_ONLY: ("aws-hosted-unverified", ""),
    E.AMAZON_ONLY: ("aws-hosted-unverified", ""),
    E.ONPREM: ("named-network", ""),
    E.REMOTE_VPC_HOST: ("own-vpc", ""),
    "10.20.1.4": ("own-vpc", ""),
    "10.10.2.7": ("own-vpc", ""),
    "10.10.1.6": ("own-vpc", ""),
}
WEEKDAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


@dataclass
class Estate:
    root: Path
    tier: str
    s3_root: Path
    inventory_path: Path
    ip_ranges_path: Path
    prices_path: Path
    intent_path: Path
    resolver_path: Path
    metrics_path: Path
    cur_path: Path
    truth_path: Path
    truth: dict[str, Any]


def _days(window: tuple[str, str]) -> list[str]:
    a, b = date.fromisoformat(window[0]), date.fromisoformat(window[1])
    return [(a + timedelta(days=i)).isoformat() for i in range((b - a).days + 1)]


def _scaled(base: int, day: str, t: dict, window: str) -> int:
    mult = t["wk"] if date.fromisoformat(day).weekday() >= 5 else 1.0
    if window == "B":
        mult *= t["growth"]
    return int(round(base * mult))


def _split(total: int, parts: int) -> list[int]:
    q, r = divmod(total, parts)
    return [q + (1 if i < r else 0) for i in range(parts)]


def _epoch(day: str, hour: int, minute: int) -> int:
    return int(datetime.fromisoformat(f"{day}T{hour:02d}:{minute:02d}:00").replace(tzinfo=UTC).timestamp())


class _Writer:
    def __init__(self, inv: dict, tier: str, rng: random.Random) -> None:
        self.inv = inv
        self.tier = tier
        self.rng = rng
        self.eni = {i["id"]: i for i in inv["interfaces"]}
        self.ranges = IpRanges(E.ip_ranges_document())
        self.rows: dict[tuple[str, str], list[dict]] = {}

    def service_of(self, ip: str) -> str | None:
        m = self.ranges.lookup(ip)
        return m.specific_services[0] if m and m.specific_services else None

    def add(
        self,
        day: str,
        hour: int,
        iface: str,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        nbytes: int,
        *,
        action: str = "ACCEPT",
        pkt_src: str | None = None,
        pkt_dst: str | None = None,
        path: int | None = None,
        svc_src: str | None = None,
        svc_dst: str | None = None,
        proto: int = 6,
    ) -> None:
        meta = self.eni[iface]
        local = set(meta["private_ips"])
        minute = self.rng.randrange(0, 59)
        rec = {
            "version": 5 if self.tier != "basic" else 2,
            "account_id": meta["account_id"],
            "interface_id": iface,
            "srcaddr": src,
            "dstaddr": dst,
            "srcport": sport,
            "dstport": dport,
            "protocol": proto,
            "packets": max(1, nbytes // 1200),
            "bytes": nbytes,
            "start": _epoch(day, hour, minute),
            "end": _epoch(day, hour, minute) + 60,
            "action": action,
            "log_status": "OK",
            "vpc_id": meta["vpc_id"],
            "subnet_id": meta["subnet_id"],
            "az_id": meta["az"],
            "flow_direction": "egress" if src in local else "ingress",
            "pkt_srcaddr": pkt_src or src,
            "pkt_dstaddr": pkt_dst or dst,
            "traffic_path": path,
            "pkt_src_aws_service": svc_src,
            "pkt_dst_aws_service": svc_dst,
            "region": meta["region"],
        }
        self.rows.setdefault((meta["account_id"], day), []).append(rec)

    def special(self, day: str, iface: str, status: str, count: int) -> None:
        meta = self.eni[iface]
        for k in range(count):
            hour = k % 24
            start = _epoch(day, hour, 5)
            rec = {f: None for f in FULL_FIELDS + DEFAULT_FIELDS}
            rec.update(
                {
                    "version": 5 if self.tier != "basic" else 2,
                    "account_id": meta["account_id"],
                    "interface_id": iface,
                    "start": start,
                    "end": start + 60,
                    "log_status": status,
                    "vpc_id": meta["vpc_id"],
                    "subnet_id": meta["subnet_id"],
                    "az_id": meta["az"],
                    "region": meta["region"],
                }
            )
            self.rows.setdefault((meta["account_id"], day), []).append(rec)


def _cell(v: Any) -> str:
    return "-" if v is None else str(v)


def _emit_exchange(w: _Writer, t: dict, day: str, c2s: int, s2c: int) -> None:
    rng = w.rng
    client, server, port = t["client"], t["server"], t["port"]
    kind = t["kind"]
    c_eni, _ = E.WORKLOADS[client]
    s_eni = E.WORKLOADS.get(server, (None,))[0] or E.ENDPOINT_ENIS.get(server)
    hours = t["hours"]
    c_parts, s_parts = _split(c2s, len(hours)), _split(s2c, len(hours))
    svc = w.service_of(server)
    if kind == "interface-endpoint":
        svc = "DYNAMODB"
    code = TRAFFIC_PATH_CODE[kind]
    for h, cb, sb in zip(hours, c_parts, s_parts, strict=True):
        for leg_bytes, outbound in ((cb, True), (sb, False)):
            for n in _split(leg_bytes, 2):
                if n == 0:
                    continue
                cport = rng.randint(32768, 60999)
                # --- observation at the client's interface
                if outbound:
                    w.add(day, h, c_eni, client, server, cport, port, n, path=code, svc_dst=svc)
                else:
                    w.add(day, h, c_eni, server, client, port, cport, n, svc_src=svc)
                # --- observation at the server-side interface when it is inside the estate
                if kind in ("intra-vpc", "transit-gateway", "interface-endpoint") and s_eni:
                    # egress from the server side is "through another resource in the same VPC" in every case
                    scode = 1
                    if outbound:
                        w.add(day, h, s_eni, client, server, cport, port, n, svc_dst=svc)
                    else:
                        w.add(day, h, s_eni, server, client, port, cport, n, path=scode, svc_src=svc)
                # --- NAT gateway interface: the NAT address is on every record, on both legs (shapes as
                # logged by a real NAT gateway; see tests/fixtures/nat_real_rows.py).
                if kind == "nat":
                    nat_ip = E.NAT_IPS[rng.randrange(len(E.NAT_IPS))]
                    nport = rng.randint(1024, 65535)
                    if outbound:
                        # workload side: workload -> NAT, pkt-dstaddr is the real remote
                        w.add(day, h, E.NAT_ENI, client, nat_ip, cport, port, n, pkt_dst=server, svc_dst=svc)
                        # internet side: NAT -> remote
                        w.add(day, h, E.NAT_ENI, nat_ip, server, nport, port, n, path=8, svc_dst=svc)
                    else:
                        # internet side: remote -> NAT
                        w.add(day, h, E.NAT_ENI, server, nat_ip, port, nport, n, svc_src=svc)
                        # workload side: NAT -> workload, pkt-srcaddr is the real remote
                        w.add(day, h, E.NAT_ENI, nat_ip, client, port, cport, n, pkt_src=server, path=1, svc_src=svc)


def _emit_rejects(w: _Writer, day: str) -> int:
    total = 0
    for target, port, count, size in (("10.10.1.5", 22, 40, 40), ("10.10.2.7", 3389, 10, 52)):
        eni = E.WORKLOADS[target][0]
        for k in range(count):
            w.add(
                day,
                3 + k % 2,
                eni,
                E.INTERNET["attacker"],
                target,
                w.rng.randint(32768, 60999),
                port,
                size,
                action="REJECT",
            )
            total += size
    return total


def _metrics(window_truth: dict) -> dict:
    m = {
        "BytesOutToDestination": window_truth["nat_out_bytes"],
        "BytesInFromDestination": window_truth["nat_in_bytes"],
        "BytesInFromSource": window_truth["nat_out_bytes"],
        "BytesOutToSource": window_truth["nat_in_bytes"],
    }
    return {
        "kind": "nat",
        "metrics": m,
        "comparable_bytes": m["BytesOutToDestination"] + m["BytesInFromDestination"],
    }


def _path_for(t: dict) -> str:
    if t["kind"] == "intra-vpc":
        a = E.WORKLOADS[t["client"]][0]
        b = E.WORKLOADS[t["server"]][0]
        inv = {i["id"]: i for i in E.inventory_document()["interfaces"]}
        return "intra-vpc-same-az" if inv[a]["az"] == inv[b]["az"] else "intra-vpc-cross-az"
    return PATH_BY_KIND[t["kind"]]


def generate(out_dir: str | Path, tier: str = "full", seed: int = 42) -> Estate:
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}")
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)  # noqa: S311 - deterministic fixtures, not security  # nosec B311 - fixtures are deterministic, not security
    inv = E.inventory_document()
    w = _Writer(inv, tier, rng)
    truth: dict[str, Any] = {
        "tier": tier,
        "seed": seed,
        "windows": {"A": list(E.WINDOW_A), "B": list(E.WINDOW_B)},
        "accounts": [E.ACCT_A, E.ACCT_B],
        "region": E.REGION,
        "nat_addresses": list(E.NAT_IPS),
        "skipdata": {
            "day": E.SKIPDATA_DAY,
            "interface_id": E.SKIPDATA_ENI,
            "records": E.SKIPDATA_RECORDS,
            "nodata_records": E.NODATA_RECORDS,
        },
        "exchanges": [],
        "by_window": {},
    }
    win_days = {"A": _days(E.WINDOW_A), "B": _days(E.WINDOW_B)}
    per_window: dict[str, dict[str, Any]] = {}
    for name, days in win_days.items():
        per_window[name] = {
            "path_bytes": {},
            "dest_bucket_bytes": {},
            "per_day": {d: 0 for d in days},
            "conversations": [],
            "nat_out_bytes": 0,
            "nat_in_bytes": 0,
            "rejected_bytes": 0,
            "rejected_records": 0,
            "service_bytes_by_path": {},
            "total_bytes": 0,
            "total_records": 0,
            "skipdata_records": 0,
            "nodata_records": 0,
            "hour_bytes": {},
            "bytes_by_client": {},
        }

    for t in E.TEMPLATES:
        path = _path_for(t)
        bucket, service = EXPECTED_DEST.get(t["server"], ("other-internet", ""))
        ex = {
            "id": t["id"],
            "client": t["client"],
            "server": t["server"],
            "port": t["port"],
            "kind": t["kind"],
            "expected_path": path,
            "expected_bucket": bucket,
            "expected_service": service,
            "ambiguous": bool(t.get("ambiguous")),
            "days": {},
        }
        for name, days in win_days.items():
            if name not in t["windows"]:
                continue
            pw = per_window[name]
            c_total = s_total = 0
            for day in days:
                c2s = _scaled(t["c2s"], day, t, name)
                s2c = _scaled(t["s2c"], day, t, name)
                _emit_exchange(w, t, day, c2s, s2c)
                ex["days"][day] = {"c2s": c2s, "s2c": s2c}
                c_total += c2s
                s_total += s2c
                pw["per_day"][day] += c2s + s2c
                share = _split(c2s + s2c, len(t["hours"]))
                for h, b in zip(t["hours"], share, strict=True):
                    key = f"{day}T{h:02d}"
                    pw["hour_bytes"][key] = pw["hour_bytes"].get(key, 0) + b
            both = c_total + s_total
            pw["path_bytes"][path] = pw["path_bytes"].get(path, 0) + both
            pw["total_bytes"] += both
            pw["dest_bucket_bytes"][bucket] = pw["dest_bucket_bytes"].get(bucket, 0) + both
            if service:
                key = f"{service}|{path}"
                pw["service_bytes_by_path"][key] = pw["service_bytes_by_path"].get(key, 0) + both
            pw["bytes_by_client"][t["client"]] = pw["bytes_by_client"].get(t["client"], 0) + both
            if t["kind"] == "nat":
                pw["nat_out_bytes"] += c_total
                pw["nat_in_bytes"] += s_total
            pw["conversations"].append(
                {
                    "id": t["id"],
                    "client": t["client"],
                    "server": t["server"],
                    "port": t["port"],
                    "c2s": c_total,
                    "s2c": s_total,
                    "path": path,
                    "ambiguous": bool(t.get("ambiguous")),
                }
            )
        truth["exchanges"].append(ex)

    for name, days in win_days.items():
        for day in days:
            rej = _emit_rejects(w, day)
            per_window[name]["rejected_bytes"] += rej
            per_window[name]["rejected_records"] += 50
        if name == "B":
            w.special(E.SKIPDATA_DAY, E.SKIPDATA_ENI, "SKIPDATA", E.SKIPDATA_RECORDS)
            w.special(E.SKIPDATA_DAY, "eni-0w3", "NODATA", E.NODATA_RECORDS)

    # --- write flow logs
    fields = TIER_FIELDS[tier]
    s3_root = root / "s3"
    counts: dict[str, int] = {}
    for (acct, day), rows in sorted(w.rows.items()):
        y, m, d = day.split("-")
        folder = s3_root / "AWSLogs" / acct / "vpcflowlogs" / E.REGION / y / m / d
        folder.mkdir(parents=True, exist_ok=True)
        lines = [" ".join(f.replace("_", "-") for f in fields)]
        rows_sorted = sorted(
            rows, key=lambda r: (r["start"], r["interface_id"], str(r["srcaddr"]), str(r["dstaddr"]))
        )
        for r in rows_sorted:
            lines.append(" ".join(_cell(r.get(f)) for f in fields))
        name = f"{acct}_vpcflowlogs_{E.REGION}_fl-0123456789abcdef0_{y}{m}{d}T0000Z_{seed:08x}.log.gz"
        with gzip.GzipFile(folder / name, "wb", mtime=0) as fh:
            fh.write(("\n".join(lines) + "\n").encode())
        counts[day] = counts.get(day, 0) + len(rows)
    for name, days in win_days.items():
        per_window[name]["total_records"] = sum(counts.get(d, 0) for d in days)
    per_window["B"]["skipdata_records"] = E.SKIPDATA_RECORDS
    per_window["B"]["nodata_records"] = E.NODATA_RECORDS
    for name in per_window:
        pw = per_window[name]
        pw["total_bytes_with_rejects"] = pw["total_bytes"] + pw["rejected_bytes"]
        pw["path_bytes"] = dict(sorted(pw["path_bytes"].items()))
    truth["by_window"] = per_window

    # --- side files
    def dump(name: str, obj: Any) -> Path:
        p = root / name
        p.write_text(json.dumps(obj, indent=2, sort_keys=True))
        return p

    inv_path = dump("inventory.json", inv)
    ipr_path = dump("ip-ranges.json", E.ip_ranges_document())
    prices_path = dump("prices.json", E.prices_document())
    res_path = dump("resolver.json", E.resolver_document())
    intent_path = root / "intent.yaml"
    intent_path.write_text(yaml.safe_dump(E.intent_document(), sort_keys=False))
    metrics = {
        "nat-0001": {
            f"{E.WINDOW_A[0]}..{E.WINDOW_A[1]}": _metrics(per_window["A"]),
            f"{E.WINDOW_B[0]}..{E.WINDOW_B[1]}": _metrics(per_window["B"]),
        }
    }
    metrics_path = dump("metrics.json", metrics)

    def cur_rows(name: str) -> list[dict]:
        pw = per_window[name]
        pre = "EUW2"
        igw_out = sum(
            ex["days"][d]["c2s"]
            for ex in truth["exchanges"]
            if ex["kind"] == "internet-gateway"
            for d in win_days[name]
            if d in ex["days"]
        )
        xaz = pw["path_bytes"].get("intra-vpc-cross-az", 0)
        return [
            {
                "account_id": E.ACCT_A,
                "usage_type": f"{pre}-NatGateway-Bytes",
                "usage_gb": pw["nat_out_bytes"] / 1e9 + pw["nat_in_bytes"] / 1e9,
            },
            {
                "account_id": E.ACCT_A,
                "usage_type": f"{pre}-DataTransfer-Out-Bytes",
                "usage_gb": pw["nat_out_bytes"] / 1e9,
            },
            {
                "account_id": E.ACCT_B,
                "usage_type": f"{pre}-DataTransfer-Out-Bytes",
                "usage_gb": igw_out / 1e9,
            },
            {
                "account_id": E.ACCT_A,
                "usage_type": f"{pre}-DataTransfer-Regional-Bytes",
                "usage_gb": xaz / 1e9,
            },
        ]

    cur = {
        f"{E.WINDOW_A[0]}..{E.WINDOW_A[1]}": cur_rows("A"),
        f"{E.WINDOW_B[0]}..{E.WINDOW_B[1]}": cur_rows("B"),
    }
    cur_path = dump("cur.json", cur)
    truth_path = dump("ground_truth.json", truth)
    return Estate(
        root,
        tier,
        s3_root,
        inv_path,
        ipr_path,
        prices_path,
        intent_path,
        res_path,
        metrics_path,
        cur_path,
        truth_path,
        truth,
    )


def main() -> None:  # pragma: no cover - convenience entry point
    import argparse

    ap = argparse.ArgumentParser(description="Generate the synthetic estate")
    ap.add_argument("out")
    ap.add_argument("--tier", default="full", choices=TIERS)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    e = generate(a.out, a.tier, a.seed)
    print(f"wrote {e.root}")


if __name__ == "__main__":  # pragma: no cover
    main()
