# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 2 (Cloud WAN prefix leak) and check 3 (blackhole) — tasks.md 1.19, 1.20."""

import copy

from drift_core.checks import EvaluationContext, check2_leak, check3_blackhole
from tests.fixtures import snapshots as fx


def ctx(cw=None, regions=None):
    return EvaluationContext(cloudwan=cw, regions=regions or {})


# ── Check 2 ──────────────────────────────────────────────────────────────────

def test_leak_no_drift_with_shares_and_static_route():
    assert check2_leak.run(ctx(fx.clean_cloudwan())) == []


def test_leak_dev_route_in_prod():
    cw = fx.clean_cloudwan()
    cw["route_tables"][0]["routes"].append(fx.cw_route("10.2.0.0/16", "dev", "attachment-0dev"))
    out = check2_leak.run(ctx(cw))
    assert [f.kind for f in out] == ["cloudwan-prefix-leak"]
    f = out[0]
    assert f.identity == tuple(sorted([f"{fx.CORE}/prod/eu-central-1", "10.2.0.0/16", "attachment-0dev"]))
    assert f.observed["source_segment"] == "dev"


def test_leak_one_finding_per_prefix_and_source():
    cw = fx.clean_cloudwan()
    for p in ("10.2.1.0/24", "10.2.2.0/24", "10.2.3.0/24"):
        cw["route_tables"][0]["routes"].append(fx.cw_route(p, "dev", "attachment-0dev"))
    out = check2_leak.run(ctx(cw))
    assert len(out) == 3 and len({f.finding_id for f in out}) == 3


def test_static_route_not_declared_is_leak():
    cw = fx.clean_cloudwan()
    cw["route_tables"][1]["routes"].append(fx.cw_route("10.99.0.0/16", "hybrid", "attachment-0hyb", rtype="STATIC"))
    assert [f.kind for f in check2_leak.run(ctx(cw))] == ["cloudwan-prefix-leak"]


def test_share_except_and_list_semantics():
    policy = copy.deepcopy(fx.POLICY)
    policy["segment-actions"] = [
        {"action": "share", "mode": "attachment-route", "segment": "shared", "share-with": {"except": ["dev"]}}]
    cw = fx.clean_cloudwan()
    cw["policy"] = policy
    cw["route_tables"] = [cw["route_tables"][1]]  # dev table only
    out = check2_leak.run(ctx(cw))
    # dev may not see shared (excepted) nor hybrid (not shared; static route no longer declared)
    assert sorted(f.observed["source_segment"] for f in out) == ["hybrid", "shared"]


def test_isolated_segment_intra_segment_vpc_route_is_leak():
    cw = fx.clean_cloudwan()
    for seg in cw["policy"]["segments"]:
        if seg["name"] == "prod":
            seg["isolate-attachments"] = True
    cw["route_tables"][0]["routes"].append(fx.cw_route("10.1.0.0/16", "prod", "attachment-0pr2"))
    out = check2_leak.run(ctx(cw))
    # Both prod VPC routes (the original 10.1.0.0/16 via 0prd and the new one via 0pr2) are leaks
    # in an isolated segment; the shared and hybrid routes are still allowed.
    assert sorted(f.kind for f in out) == ["cloudwan-isolation-leak", "cloudwan-isolation-leak"]
    assert {f.observed["source_attachment"] for f in out} == {"attachment-0prd", "attachment-0pr2"}


def test_deny_filter_overrides_share():
    cw = fx.clean_cloudwan()
    for seg in cw["policy"]["segments"]:
        if seg["name"] == "prod":
            seg["deny-filter"] = ["shared"]
    out = check2_leak.run(ctx(cw))
    # prod's 10.3.0.0/16 from 'shared' is now a leak: the '*' share is filtered by prod's deny-filter
    assert [(f.kind, f.observed["source_segment"]) for f in out] == [("cloudwan-prefix-leak", "shared")]


def test_allow_filter_restricts_shares():
    cw = fx.clean_cloudwan()
    for seg in cw["policy"]["segments"]:
        if seg["name"] == "dev":
            seg["allow-filter"] = ["hybrid"]  # dev may only receive from hybrid
    out = check2_leak.run(ctx(cw))
    assert [(f.context["segment"], f.observed["source_segment"]) for f in out] == [("dev", "shared")]


def test_isolated_segment_ignores_static_and_non_vpc():
    cw = fx.clean_cloudwan()
    for seg in cw["policy"]["segments"]:
        if seg["name"] == "prod":
            seg["isolate-attachments"] = True
    cw["route_tables"][0]["routes"] = [
        fx.cw_route("10.1.0.0/16", "prod", "attachment-0prd", rtype="STATIC"),
        fx.cw_route("10.8.0.0/16", "prod", "attachment-0vpn", resource_type="site-to-site-vpn")]
    assert check2_leak.run(ctx(cw)) == []


def test_leak_ignores_blackhole_and_same_segment():
    cw = fx.clean_cloudwan()
    cw["route_tables"][0]["routes"].append(fx.cw_route("10.2.0.0/16", "dev", "attachment-0dev", state="BLACKHOLE"))
    cw["route_tables"][0]["routes"].append(fx.cw_route("10.1.9.0/24", "prod", "attachment-0prd"))
    assert check2_leak.run(ctx(cw)) == []
    assert check2_leak.run(ctx(None)) == []


# ── Check 3 ──────────────────────────────────────────────────────────────────

def test_blackhole_none_when_clean():
    assert check3_blackhole.run(ctx(fx.clean_cloudwan(), {"eu-central-1": fx.clean_region()})) == []


def test_blackhole_tgw_static_and_propagated():
    r = fx.clean_region()
    r["route_tables"][0]["routes"] += [
        fx.tgw_route("10.100.5.0/24", "tgw-attach-0prd", state="blackhole", rtype="static"),
        fx.tgw_route("10.100.6.0/24", "tgw-attach-0prd", state="blackhole", rtype="propagated"),
    ]
    out = check3_blackhole.run(ctx(None, {"eu-central-1": r}))
    assert [f.kind for f in out] == ["blackhole-route", "blackhole-route"]
    assert {f.observed["type"] for f in out} == {"static", "propagated"}
    assert all(f.context["platform"] == "tgw" for f in out)


def test_blackhole_cloudwan():
    cw = fx.clean_cloudwan()
    cw["route_tables"][0]["routes"].append(fx.cw_route("10.9.0.0/16", "prod", "attachment-0prd", state="BLACKHOLE",
                                                       rtype="STATIC"))
    out = check3_blackhole.run(ctx(cw))
    assert len(out) == 1 and out[0].region == "eu-central-1" and out[0].context["segment"] == "prod"
