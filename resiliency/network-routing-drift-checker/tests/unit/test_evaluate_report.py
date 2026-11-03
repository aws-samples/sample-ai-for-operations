# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Evaluation wiring and message composition (tasks.md 1.22, 1.26; requirements §10.2, §14.6)."""

from drift_core import report
from drift_core.diff import compute
from drift_core.evaluate import evaluate
from tests.fixtures import snapshots as fx

NOW = "2026-05-12T05:00:00Z"
URI = "s3://bucket/runs/r1/findings.json"


def manifest(intent_status="absent", errors=None, dx_status="ok"):
    return {"tag_key": "Environment", "limit_threshold_percent": 80.0, "limit_threshold_overrides": {},
            "intent": {"status": intent_status, "errors": errors or []}, "dx_gateways": {"status": dx_status}}


def run(cloudwan=None, regions=None, man=None, not_evaluated=None, cloudwan_error=None):
    ev = evaluate(cloudwan, regions or {}, man or manifest(), not_evaluated or {}, cloudwan_error)
    d = compute([x.to_dict() for x in ev.findings], [], set(regions or {}) | {"global", "cloudwan"}, NOW, "r1")
    return ev, d


def compose(ev, d, **kw):
    return report.compose(date="2026-05-12", run_id="r1", evaluation=ev.to_dict(), diff=d.to_dict(),
                          findings_uri=URI, **kw)


def test_clean_run_heartbeat_with_skipped_checks_line():
    ev, d = run(fx.clean_cloudwan(), {"eu-central-1": fx.clean_region()})
    rep = compose(ev, d)
    assert rep.kind == "heartbeat" and rep.subject == "Network routing drift check 2026-05-12: no drift"
    first = rep.body.splitlines()[0]
    assert "no drift" in first and "4 of 6 checks run" in first
    assert "3 checks skipped (intent file absent)" in first
    assert f"{ev.resources_evaluated} resources evaluated" in first and ev.resources_evaluated > 0


def test_valid_intent_has_no_skipped_line():
    m = manifest("ok")
    m["intent"]["model"] = {"version": 1, "tgw_isolation": {}, "dx_redundancy_pairs": [], "hybrid_paths": [],
                            "regions": {"allow": [], "exclude": []}, "lines": {}}
    ev, d = run(fx.clean_cloudwan(), man=m)
    first = compose(ev, d).body.splitlines()[0]
    assert "6 of 6 checks run" in first and "skipped" not in first


def test_region_not_evaluated_line_and_never_clean():
    ev, d = run(fx.clean_cloudwan(), {"eu-central-1": fx.clean_region()},
                not_evaluated={"eu-west-1": "ThrottlingException"})
    rep = compose(ev, d)
    assert rep.kind == "heartbeat" and "(1 not verified)" in rep.subject
    assert "Regions not evaluated: eu-west-1" in rep.body
    assert "- Region eu-west-1 not evaluated: ThrottlingException" in rep.body


def test_intent_rejected_cloudwan_and_dx_errors_surface():
    ev, d = run(None, {}, man=manifest("rejected", ["line 3, column 1: mapping values are not allowed"],
                                        dx_status="error"), cloudwan_error="AccessDeniedException")
    kinds = sorted(x.kind for x in ev.findings)
    assert kinds == ["cloudwan-not-evaluated", "dx-gateways-not-evaluated", "intent-file-rejected"]
    body = compose(ev, d).body
    assert "Intent file rejected: line 3" in body and "Cloud WAN not evaluated: AccessDeniedException" in body


def test_truncated_table_is_a_system_finding():
    r = fx.clean_region()
    r["route_tables"][0]["routes_truncated"] = True
    ev, _ = run(None, {"eu-central-1": r})
    assert [x.kind for x in ev.findings] == ["routes-truncated"]


def test_drift_report_without_handoff_states_no_investigation():
    r = fx.clean_region()
    r["route_tables"][0]["routes"].append(fx.tgw_route("10.9.0.0/16", "tgw-attach-0prd", state="blackhole",
                                                       rtype="static"))
    ev, d = run(None, {"eu-central-1": r})
    rep = compose(ev, d)
    assert rep.kind == "drift" and "1 new, 0 known, 0 resolved" in rep.subject
    assert report.NO_HANDOFF in rep.body and "\nNEW (1)\n" in rep.body
    assert rep.body.rstrip().endswith(URI)


def test_drift_report_known_resolved_and_no_new_with_handoff():
    known = {"finding_id": "f-a", "kind": "blackhole-route", "severity": "drift", "region": "eu-central-1",
             "message": "m", "first_seen": "2026-05-01T05:00:00Z", "age_days": 11, "changed": True,
             "unverified": True}
    resolved = dict(known, finding_id="f-b", changed=False, unverified=False)
    diff = {"new": [], "known": [known], "resolved": [resolved]}
    ev, _ = run(fx.clean_cloudwan())
    rep = report.compose(date="2026-05-12", run_id="r1", evaluation=ev.to_dict(), diff=diff, findings_uri=URI,
                         handoff_enabled=True)
    assert report.NO_NEW in rep.body
    assert "first seen 2026-05-01 (11 days); changed since last run; not re-verified" in rep.body
    assert "\nRESOLVED (1)\n" in rep.body


def test_informational_counted_not_drift():
    r = fx.clean_region()
    r["attachments"][0]["tags"] = {}
    ev, d = run(None, {"eu-central-1": r})
    rep = compose(ev, d)
    assert rep.kind == "heartbeat" and "Informational: 1 new, 0 known" in rep.body


def test_body_capped_with_pointer():
    r = fx.clean_region()
    r["route_tables"][0]["routes"] += [fx.tgw_route(f"10.{i // 250}.{i % 250}.0/24", "tgw-attach-0prd",
                                                    state="blackhole", rtype="static") for i in range(3000)]
    ev, d = run(None, {"eu-central-1": r})
    body = compose(ev, d).body
    assert len(body.encode()) <= report.BODY_MAX_BYTES and "message truncated" in body and URI in body


def test_emf_line():
    line = report.emf_metrics("NS", {"FindingsNew": 2, "RunDurationSeconds": 3.5}, 1700000000000)
    assert '"Namespace": "NS"' in line and '"Unit": "Seconds"' in line and '"FindingsNew": 2' in line
