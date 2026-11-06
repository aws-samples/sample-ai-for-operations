#!/usr/bin/env python3
# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Collect the network inventory (provider C) with read-only EC2 describe calls.

Run it with whatever credentials already reach the account, then hand the JSON to the agent
(``NFI_INVENTORY_FILE``). It needs only boto3. The calls are ``ec2:Describe*`` plus
``ec2:GetManagedPrefixListEntries``; nothing is created or changed.

    python scripts/collect_inventory.py --region eu-west-2 --region us-east-1 --out inventory-111111111111.json

To cover several accounts, run it once per account and merge with ``--merge a.json b.json``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

_MODULE = (
    Path(__file__).resolve().parent.parent / "src" / "network_flow_insight" / "core" / "inventory" / "ec2.py"
)
_SECTIONS = (
    "vpcs",
    "subnets",
    "route_tables",
    "interfaces",
    "nat_gateways",
    "endpoints",
    "prefix_lists",
    "tgw_attachments",
)


def _load_collector():
    try:
        from network_flow_insight.core.inventory import ec2  # installed package

        return ec2
    except ImportError:
        spec = importlib.util.spec_from_file_location("nfi_inventory_ec2", _MODULE)
        if spec is None or spec.loader is None:
            raise SystemExit(f"cannot find the collector at {_MODULE}") from None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


def merge(paths: list[str]) -> dict:
    docs = [json.loads(Path(p).read_text()) for p in paths]
    out = {
        "schema_version": 1,
        "source": "file",
        "collected_at": max(d.get("collected_at", "") for d in docs),
    }
    for sec in _SECTIONS:
        seen: set[str] = set()
        out[sec] = []
        for d in docs:
            for item in d.get(sec, []):
                if item["id"] not in seen:
                    seen.add(item["id"])
                    out[sec].append(item)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--region", action="append", help="Region to collect (repeatable); default: the session Region"
    )
    ap.add_argument("--profile", help="named AWS profile")
    ap.add_argument("--out", default="-", help="output file, or - for stdout")
    ap.add_argument(
        "--merge",
        nargs="+",
        metavar="FILE",
        help="merge inventory files from several accounts instead of collecting",
    )
    args = ap.parse_args(argv)
    if args.merge:
        doc = merge(args.merge)
    else:
        import boto3

        session = boto3.Session(profile_name=args.profile)
        regions = args.region or [session.region_name or "us-east-1"]
        doc = _load_collector().collect(session, regions)
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.out == "-":
        sys.stdout.write(text + "\n")
    else:
        Path(args.out).write_text(text + "\n")
        print(
            f"wrote {args.out}: {len(doc['interfaces'])} interfaces, {len(doc['nat_gateways'])} NAT gateways",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
