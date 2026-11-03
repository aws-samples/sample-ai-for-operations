# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 5 — limits (tasks.md 1.21)."""

import pytest

from drift_core.checks import EvaluationContext, check5_limits
from drift_core.limits import REGISTRY, percent
from tests.fixtures import snapshots as fx


def _dx_region(n_ipv4, ipv4_alloc=None, ipv6_routes=0, ipv6_alloc=None):
    routes = [fx.tgw_route(f"192.168.{i}.0/24", "tgw-attach-0dxg", resource_type="direct-connect-gateway",
                           resource_id="dxgw-0aaa") for i in range(n_ipv4)]
    routes += [fx.tgw_route(f"2001:db8:{i:x}::/48", "tgw-attach-0dxg", resource_type="direct-connect-gateway",
                            resource_id="dxgw-0aaa") for i in range(ipv6_routes)]
    return fx.region(route_tables=[fx.tgw_table("tgw-rtb-0hyb", "shared", routes)],
                     vifs=[fx.vif("dxvif-0aaa", ipv4=ipv4_alloc, ipv6=ipv6_alloc)])


def _run(regions=None, cw=None, **kw):
    return check5_limits.run(EvaluationContext(cloudwan=cw, regions=regions or {}, **kw))


def test_registry_has_five_documented_limits():
    assert len(REGISTRY) == 5 and all(limit.doc_url.startswith("https://docs.aws.amazon.com/") for limit in REGISTRY)


def test_percent():
    assert percent(80, 100) == 80.0 and percent(1, 3) == 33.3 and percent(5, 0) == 100.0


@pytest.mark.parametrize("count,fires", [(79, False), (80, True), (95, True)])
def test_onprem_to_aws_threshold_with_assumed_default(count, fires):
    out = _run({"eu-central-1": _dx_region(count)})
    assert bool(out) is fires
    if fires:
        f = out[0]
        assert f.message.startswith("Approximate:")
        assert "approximate" in f.message.lower()
        assert f.context["limit_basis"] == "assumed-default" and f.observed["limit"] == 100


def test_onprem_to_aws_uses_configured_allocation():
    assert _run({"eu-central-1": _dx_region(90, ipv4_alloc=1000)}) == []
    out = _run({"eu-central-1": _dx_region(850, ipv4_alloc=1000)})
    assert out[0].observed == {"count": 850, "limit": 1000, "percent": 85.0}
    assert out[0].context["limit_basis"] == "configured"


def test_onprem_to_aws_ipv6_separate_family():
    out = _run({"eu-central-1": _dx_region(10, ipv6_routes=9, ipv6_alloc=10)})
    assert [f.context["address_family"] for f in out] == ["ipv6"]


def test_finding_id_stable_as_count_climbs():
    a = _run({"eu-central-1": _dx_region(81)})[0]
    b = _run({"eu-central-1": _dx_region(99)})[0]
    assert a.finding_id == b.finding_id and a.payload_hash != b.payload_hash


def test_private_vif_and_override_threshold():
    r = _dx_region(85)
    r["dx_virtual_interfaces"][0]["type"] = "private"
    assert _run({"eu-central-1": r}) == []
    assert _run({"eu-central-1": _dx_region(85)}, limit_threshold_overrides={"dx-onprem-to-aws-per-bgp-session": 90}) \
        == []


def test_tgw_to_onprem_allowed_prefixes():
    assoc = {"association_id": "dxgw-assoc-1", "dxgw_id": "dxgw-0aaa", "associated_gateway_id": "tgw-0aaa",
             "associated_gateway_type": "transitGateway", "state": "associated",
             "allowed_prefixes": [f"10.{i}.0.0/16" for i in range(170)]}
    out = _run({"eu-central-1": fx.region(associations=[assoc]), "eu-west-1": fx.region(associations=[assoc])})
    assert len(out) == 1 and out[0].observed["limit"] == 200 and out[0].observed["percent"] == 85.0
    vgw = dict(assoc, association_id="x", associated_gateway_type="virtualPrivateGateway")
    assert _run({"eu-central-1": fx.region(associations=[vgw])}) == []


def test_tgw_total_routes():
    routes = [fx.tgw_route(f"10.{i // 250}.{i % 250}.0/24", "tgw-attach-0prd") for i in range(8100)]
    out = _run({"eu-central-1": fx.region(route_tables=[fx.tgw_table("tgw-rtb-0prd", "prod", routes)])})
    assert [f.context["limit_name"] for f in out] == ["tgw-total-routes"]


def test_cloudwan_totals_and_to_onprem():
    cw = fx.clean_cloudwan()
    big = [fx.cw_route(f"10.{i // 250}.{i % 250}.0/24", "prod", "attachment-0prd") for i in range(8100)]
    cw["route_tables"].append({"segment": "hybrid", "edge": "eu-central-1", "routes": big})
    names = sorted(f.context["limit_name"] for f in _run(cw=cw, limit_threshold_overrides={
        "dx-cloudwan-to-onprem-prefixes": 50}))
    assert names == ["cloudwan-total-routes", "dx-cloudwan-to-onprem-prefixes"]
    assert _run(cw=fx.clean_cloudwan()) == []
