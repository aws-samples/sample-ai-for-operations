# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`collect-cloudwan` and `collect-region` (design.md D§2.1). Read-only collection -> S3 snapshot.

Errors propagate on purpose: the state machine retries throttling, then its Catch records
"not evaluated" for that Region (or Cloud WAN) and the run continues (requirements §9.1).
"""

from __future__ import annotations

from typing import Any

from config import load_settings
from drift_core.artifacts import Artifacts
from drift_core.collectors import cloudwan, directconnect, tgw
from drift_core.collectors.errors import classified
from drift_core.evaluate import count_resources
from drift_core.logging_util import get_logger, log_event
from drift_core.run_info import REGION_RE, InputError
from handlers import aws_clients


def _artifacts(event: dict[str, Any]) -> Artifacts:
    run_id = event.get("run_id") if isinstance(event, dict) else None
    if not run_id or not isinstance(run_id, str):
        raise InputError("run_id is required")
    return Artifacts(aws_clients.client("s3"), load_settings().require("bucket_name"), run_id)


@classified
def cloudwan_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    log = get_logger("collect-cloudwan", load_settings().log_level)
    artifacts = _artifacts(event)
    manifest = artifacts.get_json("manifest.json")
    core_id = (manifest.get("cloudwan") or {}).get("core_network_id")
    raw = cloudwan.fetch(aws_clients.client("networkmanager", cloudwan.HOME_REGION), core_id)
    snapshot = cloudwan.normalize(raw)
    artifacts.put_json("cloudwan.json", snapshot)
    status = "ok" if snapshot else "absent"
    log_event(log, "cloudwan_collected", run_id=artifacts.run_id, status=status,
              resources=count_resources(snapshot, {}))
    return {"status": status}


@classified
def region_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    log = get_logger("collect-region", load_settings().log_level)
    artifacts = _artifacts(event)
    region = event.get("region")
    if not isinstance(region, str) or not REGION_RE.match(region):
        raise InputError("region is required")
    gateways = artifacts.get_json("dx_gateways.json")
    ec2 = aws_clients.client("ec2", region)
    tgw_raw = tgw.fetch_region(ec2)
    vpn_raw = tgw.fetch_vpn(ec2)
    dx_raw = directconnect.fetch_region(aws_clients.client("directconnect", region))
    snapshot = {"region": region, **tgw.normalize_region(tgw_raw), **tgw.normalize_vpn(vpn_raw),
                **directconnect.normalize_region(region, dx_raw, gateways)}
    artifacts.put_json(f"regions/{region}.json", snapshot)
    resources = count_resources(None, {region: snapshot})
    log_event(log, "region_collected", run_id=artifacts.run_id, region=region, resources=resources)
    return {"region": region, "status": "ok", "resources": resources}
