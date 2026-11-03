# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Collectors normalized from REAL recorded responses (tests/fixtures/recorded/raw_responses.json).

The recording comes from a non-production lab account via scripts/record_fixtures.py
(read-only calls, sanitized before write). It contains real drift: static blackhole routes.
"""

import json
import pathlib

import pytest

from drift_core.checks import EvaluationContext, check1_domain, check2_leak, check3_blackhole, check5_limits
from drift_core.collectors import cloudwan, directconnect, tgw

RECORDED = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "recorded" / "raw_responses.json"


@pytest.fixture(scope="module")
def raw():
    return json.loads(RECORDED.read_text())


@pytest.fixture(scope="module")
def regions(raw):
    out = {}
    for name, data in raw["regions"].items():
        snap = {"region": name, **tgw.normalize_region(data["tgw"]),
                **directconnect.normalize_region(name, data["dx"], raw["dx_gateways"])}
        out[name] = snap
    return out


def test_tgw_normalization_shapes(regions):
    eu = regions["eu-central-1"]
    assert len(eu["transit_gateways"]) == 2 and len(eu["route_tables"]) == 5
    for table in eu["route_tables"]:
        assert table["route_table_id"].startswith("tgw-rtb-") and table["tgw_id"].startswith("tgw-")
        assert table["routes_truncated"] is False
        for route in table["routes"]:
            assert route["state"] in ("active", "blackhole") and route["type"] in ("propagated", "static")
    us = regions["us-east-1"]
    att = us["attachments"][0]
    assert att["resource_type"] == "vpc" and att["association"]["state"] == "associated"


def test_recorded_blackholes_are_found(regions):
    findings = check3_blackhole.run(EvaluationContext(cloudwan=None, regions=regions))
    by_region = {}
    for f in findings:
        by_region[f.region] = by_region.get(f.region, 0) + 1
    assert by_region == {"eu-central-1": 5, "us-east-1": 1}
    assert {f.observed["type"] for f in findings} == {"static"}
    assert len({f.finding_id for f in findings}) == 6


def test_blackhole_route_has_no_attachments_and_does_not_break_check2(regions):
    blackholes = [r for t in regions["eu-central-1"]["route_tables"] for r in t["routes"] if r["state"] == "blackhole"]
    assert blackholes and all(r["attachments"] == [] for r in blackholes)
    assert check2_leak.run(EvaluationContext(cloudwan=None, regions=regions)) == []


def test_untagged_lab_tables_reported_once_each(regions):
    out = check1_domain.check_tgw(EvaluationContext(cloudwan=None, regions=regions))
    # The lab uses only Name tags, so the one associated attachment's table is reported as untagged.
    assert [f.kind for f in out] == ["untagged-route-table"]
    assert out[0].region == "us-east-1" and len(out[0].observed["attachments"]) == 1


def test_dx_global_gateways_without_associations(raw, regions):
    assert len(raw["dx_gateways"]["gateways"]) == 2
    assert directconnect.association_regions(raw["dx_gateways"]) == set()
    assert all(r["dx_virtual_interfaces"] == [] and r["dx_gateway_associations"] == [] for r in regions.values())


def test_cloudwan_normalization(raw):
    snap = cloudwan.normalize(raw["cloudwan"])
    assert snap["core_network_id"].startswith("core-network-")
    assert snap["global_network_id"].startswith("global-network-")
    assert snap["home_region"] == "us-west-2"
    assert snap["route_tables"] == [{"segment": "dev", "edge": "us-east-1", "routes": []}]
    assert snap["attachments"] == [] and isinstance(snap["policy"], dict)
    assert cloudwan.edge_regions(raw["cloudwan"]) == {"us-east-1"}


def test_full_phase1_pass_on_recording_is_deterministic(raw, regions):
    cw = cloudwan.normalize(raw["cloudwan"])
    ctx = EvaluationContext(cloudwan=cw, regions=regions)
    run = lambda: sorted(f.finding_id for m in (check1_domain, check2_leak, check3_blackhole, check5_limits)  # noqa: E731
                         for f in m.run(ctx))
    assert run() == run() and len(run()) == 7
