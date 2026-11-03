# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Intent-dependent checks wired into evaluate and the report (tasks.md 2.6)."""

from drift_core import report
from drift_core.diff import compute
from drift_core.evaluate import evaluate
from drift_core.intent import parse
from tests.fixtures import snapshots as fx

INTENT = parse("version: 1\ntgw_isolation:\n  prod: [prod]\n  dev: [dev]\n"
               "dx_redundancy_pairs:\n  - name: site-a\n    members: [dxvif-0001, dxvif-0002]\n")


def manifest(load):
    return {"tag_key": "Environment", "limit_threshold_percent": 80.0, "limit_threshold_overrides": {},
            "intent": load.manifest_entry(), "dx_gateways": {"status": "ok"}}


def body(ev):
    d = compute([f.to_dict() for f in ev.findings], [], {"eu-central-1", "global", "cloudwan"},
                "2026-10-13T05:00:00Z", "r1")
    return report.compose(date="2026-10-13", run_id="r1", evaluation=ev.to_dict(), diff=d.to_dict(),
                          findings_uri="s3://b/f.json")


def test_valid_intent_runs_all_six_checks():
    r = fx.clean_region()
    r["dx_virtual_interfaces"] = [fx.vif("dxvif-0001"), fx.vif("dxvif-0002")]
    ev = evaluate(None, {"eu-central-1": r}, manifest(INTENT), {})
    assert ev.checks_run == ["check1", "check2", "check3", "check5", "check2-tgw", "check4", "check6"]
    assert ev.checks_skipped == [] and ev.skip_reason is None and ev.findings == []
    first = body(ev).body.splitlines()[0]
    assert "6 of 6 checks run" in first and "skipped" not in first


def test_intent_drift_reaches_report():
    r = fx.clean_region()
    r["dx_virtual_interfaces"] = [fx.vif("dxvif-0001", state="down")]
    ev = evaluate(None, {"eu-central-1": r}, manifest(INTENT), {})
    assert sorted(f.kind for f in ev.findings) == ["redundancy-member-down", "redundancy-member-missing",
                                                   "redundancy-pair-down"]
    assert "3 new" in body(ev).subject


def test_unresolvable_isolation_name_rejects_file_but_phase1_still_runs():
    load = parse("version: 1\ntgw_isolation:\n  prod: [prod, staging]\n")
    r = fx.clean_region()
    r["route_tables"][0]["routes"].append(fx.tgw_route("10.9.0.0/16", "tgw-attach-0prd", state="blackhole"))
    ev = evaluate(None, {"eu-central-1": r}, manifest(load), {})
    kinds = sorted(f.kind for f in ev.findings)
    assert kinds == ["blackhole-route", "intent-file-rejected"]
    rejected = next(f for f in ev.findings if f.kind == "intent-file-rejected")
    assert rejected.message.startswith("Intent file rejected: line 3: tgw_isolation.prod: 'staging'")
    assert ev.skip_reason == "intent file rejected" and len(ev.checks_skipped) == 3
    text = body(ev).body
    assert "NOT VERIFIED (1)" in text and "Intent file rejected: line 3" in text


def test_name_resolution_skipped_while_a_region_is_not_evaluated():
    load = parse("version: 1\ntgw_isolation:\n  prod: [prod]\n  staging: [staging]\n")
    ev = evaluate(None, {"eu-central-1": fx.clean_region()}, manifest(load), {"eu-west-1": "throttled"})
    assert "intent-file-rejected" not in {f.kind for f in ev.findings} and ev.skip_reason is None
