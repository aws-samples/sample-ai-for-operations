# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""`init`: load the intent file, discover Region scope, write the run manifest (design.md D§2.1, D§3.1)."""

from __future__ import annotations

import concurrent.futures as cf
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from config import load_settings
from drift_core.artifacts import Artifacts, read_intent
from drift_core.collectors import cloudwan, directconnect
from drift_core.intent import IntentLoad, parse
from drift_core.logging_util import get_logger, log_event
from drift_core.regions import enabled_regions, has_transit_gateway, resolve_scope
from drift_core.run_info import RunInfo, default_lookback
from drift_core.state_store import StateStore
from handlers import aws_clients

_AWS_ERRORS = (ClientError, BotoCoreError)


def _load_intent(s3: Any, bucket: str, key: str) -> IntentLoad:
    status, text, version_id, error = read_intent(s3, bucket, key)
    if status == "found":
        return parse(text or "", version_id)
    if status == "absent":
        return IntentLoad("absent")
    return IntentLoad("unreadable", errors=[f"could not read the intent file ({error})"])


def region_lists(intent: IntentLoad, stack_allow: tuple[str, ...], stack_exclude: tuple[str, ...]
                 ) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Intent file `regions` (when valid and non-empty) replaces the matching stack parameter
    (tasks.md 2.5). Precedence overall: execution input > intent file > stack parameters > discovery."""
    regions = (intent.document or {}).get("regions") or {} if intent.status == "ok" else {}
    allow = tuple(regions.get("allow") or ()) or stack_allow
    exclude = tuple(regions.get("exclude") or ()) or stack_exclude
    return allow, exclude


def referenced_vifs(intent: IntentLoad) -> set[str]:
    """VIF IDs the intent file names (redundancy pairs, preferred/backup paths)."""
    model = intent.document or {} if intent.status == "ok" else {}
    ids = {m for pair in model.get("dx_redundancy_pairs") or [] for m in pair["members"]}
    ids |= {p[k] for p in model.get("hybrid_paths") or [] for k in ("preferred", "backup")
            if str(p.get(k, "")).startswith("dxvif-")}
    return {i.lower() for i in ids}


def _vif_regions(regions: list[str], wanted: set[str], log: logging.Logger) -> set[str]:
    """Regions that own a VIF the intent file names. A VIF can live in a Region with no transit
    gateway, so discovery would otherwise miss it and report the pair member as missing.
    A Region that cannot be probed is INCLUDED (fail-closed), like the TGW probe."""
    def probe(region: str) -> tuple[str, bool]:
        try:
            found = aws_clients.client("directconnect", region).describe_virtual_interfaces().get(
                "virtualInterfaces") or []
            return region, any(v.get("virtualInterfaceId", "").lower() in wanted for v in found)
        except _AWS_ERRORS as exc:
            log_event(log, "vif_probe_failed", logging.WARNING, region=region, error=type(exc).__name__)
            return region, True

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        return {region for region, present in pool.map(probe, regions) if present}


def _tgw_regions(regions: list[str], log: logging.Logger) -> set[str]:
    """Regions with a TGW. A Region that cannot be probed is INCLUDED (fail-closed): its
    collection then fails visibly as 'Region not evaluated' instead of being skipped as clean."""
    def probe(region: str) -> tuple[str, bool]:
        try:
            return region, has_transit_gateway(aws_clients.client("ec2", region))
        except _AWS_ERRORS as exc:
            log_event(log, "tgw_probe_failed", logging.WARNING, region=region, error=type(exc).__name__)
            return region, True

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        return {region for region, present in pool.map(probe, regions) if present}


def handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    settings = load_settings()
    log = get_logger("init", settings.log_level)
    run = RunInfo.from_event(event)
    bucket = settings.require("bucket_name")
    s3 = aws_clients.client("s3")
    artifacts = Artifacts(s3, bucket, run.run_id)

    intent = _load_intent(s3, bucket, settings.intent_object_key)

    try:
        cw = cloudwan.discover(aws_clients.client("networkmanager", cloudwan.HOME_REGION))
        cw_status, cw_error = ("present" if cw else "absent"), None
    except _AWS_ERRORS as exc:
        cw, cw_status, cw_error = None, "unknown", type(exc).__name__
        log_event(log, "cloudwan_discovery_failed", logging.WARNING, error=cw_error)

    try:
        dx_raw = directconnect.fetch_gateways(aws_clients.client("directconnect"))
        dx_entry: dict[str, Any] = {"status": "ok"}
    except _AWS_ERRORS as exc:
        dx_raw, dx_entry = {"gateways": [], "associations": []}, {"status": "error", "error": type(exc).__name__}
        log_event(log, "dx_gateway_discovery_failed", logging.WARNING, error=dx_entry["error"])

    enabled = enabled_regions(aws_clients.client("ec2"))  # no Region list -> the run cannot be scoped: fail
    allowlist, exclude = region_lists(intent, settings.region_allowlist, settings.region_exclude_list)
    discover = not run.override_regions and not allowlist
    tgw_regions = _tgw_regions(enabled, log) if discover else set()
    wanted_vifs = referenced_vifs(intent) if discover else set()
    vif_regions = _vif_regions(enabled, wanted_vifs, log) if wanted_vifs else set()
    scope = resolve_scope(enabled, tgw_regions, set((cw or {}).get("edge_locations") or []),
                          directconnect.association_regions(dx_raw) | vif_regions, allowlist, exclude,
                          run.override_regions)

    lookback = (run.override_lookback_from or StateStore(aws_clients.table(settings.require("table_name"))).get_marker()
                or default_lookback(run.started_at))

    manifest = {
        "run_id": run.run_id, "started_at": run.started_at, "scope": run.scope,
        "regions": {"evaluate": list(scope.evaluate), "excluded": list(scope.excluded), "source": scope.source},
        "cloudwan": {"status": cw_status, "error": cw_error, **(cw or {})},
        "dx_gateways": dx_entry,
        "intent": intent.manifest_entry(),
        "lookback_from": lookback,
        "tag_key": settings.environment_tag_key,
        "production_tag_values": list(settings.production_tag_values),
        "limit_threshold_percent": settings.limit_threshold_percent,
        "limit_threshold_overrides": settings.limit_threshold_overrides,
        "handoff_enabled": settings.handoff_enabled,
    }
    artifacts.put_json("manifest.json", manifest)
    artifacts.put_json("dx_gateways.json", dx_raw)
    log_event(log, "run_initialized", run_id=run.run_id, scope=run.scope, regions=list(scope.evaluate),
              cloudwan=cw_status, intent=intent.status)
    return {"run_id": run.run_id, "started_at": run.started_at, "scope": run.scope,
            "regions": list(scope.evaluate), "collect_cloudwan": cw_status != "absent",
            "concurrency": settings.region_concurrency, "handoff_enabled": settings.handoff_enabled}
