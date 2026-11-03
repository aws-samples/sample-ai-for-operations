# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Record real, read-only API responses as sanitized test fixtures (tasks.md 1.12-1.14).

Usage:
    .venv/bin/python scripts/record_fixtures.py --profile <readonly-profile> \
        --regions eu-central-1,us-east-1 [--out tests/fixtures/recorded]

Only Describe/Get/List/Search calls are made (the same collectors the Lambda runs).
Responses are sanitized in memory (scripts/sanitize.py) and verified leak-free before
anything is written. Review the output before committing it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

import boto3

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from sanitize import Sanitizer, leaks  # noqa: E402

from drift_core.collectors import CLIENT_CONFIG, cloudwan, directconnect, tgw  # noqa: E402


def _json_default(value):
    if isinstance(value, (dt.datetime, dt.date)):
        return "2026-01-01T00:00:00+00:00"  # timestamps are not structural; normalize them
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", required=True)
    parser.add_argument("--regions", required=True, help="comma-separated Regions to record")
    parser.add_argument("--out", default="tests/fixtures/recorded")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile)
    account = session.client("sts", config=CLIENT_CONFIG).get_caller_identity()["Account"]
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    raw: dict = {"regions": {}}
    dx_global = directconnect.fetch_gateways(session.client("directconnect", region_name=regions[0],
                                                            config=CLIENT_CONFIG))
    raw["dx_gateways"] = dx_global
    for region in regions:
        raw["regions"][region] = {
            "tgw": tgw.fetch_region(session.client("ec2", region_name=region, config=CLIENT_CONFIG)),
            "dx": directconnect.fetch_region(session.client("directconnect", region_name=region,
                                                            config=CLIENT_CONFIG)),
        }
    raw["cloudwan"] = cloudwan.fetch(session.client("networkmanager", region_name=cloudwan.HOME_REGION,
                                                    config=CLIENT_CONFIG))

    plain = json.loads(json.dumps(raw, default=_json_default))
    sanitizer = Sanitizer()
    clean = sanitizer(plain)
    real = {account, *sanitizer.accounts, *sanitizer.ids, *sanitizer.uuids, *sanitizer.ips}
    found = leaks(clean, real)
    if found:
        print(f"ABORT: {len(found)} real value(s) survived sanitization; nothing written.", file=sys.stderr)
        return 2

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "raw_responses.json").write_text(json.dumps(clean, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out / 'raw_responses.json'}: regions={len(regions)} "
          f"ids_mapped={len(sanitizer.ids)} accounts_mapped={len(sanitizer.accounts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
