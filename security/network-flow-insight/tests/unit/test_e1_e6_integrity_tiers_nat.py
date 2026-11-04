# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""E1 tiers, E2 integrity, E4 reconciliation, E4a providers, E4b pairing, E5 classification, E6 endpoints."""

import json

import pytest

from network_flow_insight.config import Settings
from network_flow_insight.core.inventory import Inventory
from network_flow_insight.core.ipranges import IpRanges
from network_flow_insight.demo import estate as E
from network_flow_insight.tools import (
    assign_tier,
    classify_destination,
    classify_path,
    detect_forwarding_interfaces,
    nat_leg_check,
    nat_scope,
    reconcile,
)
from network_flow_insight.tools.reconcile import diagnose_ratio

B = E.WINDOW_B


def _rows(a):
    wd = a.window_data(*B)
    return wd.rows


# ---------------------------------------------------------------------------------- E1


@pytest.mark.parametrize(
    "tier, provider, expected_tier, unavailable, inferred",
    [
        (
            "basic",
            "D",
            "basic-no-inventory",
            ["endpoint_effectiveness"],
            [
                "aws_service_reach",
                "dependency_view",
                "destination_classification",
                "gateway_inventory",
                "inter_vpc_cross_region",
                "nat_scoped_analysis",
                "nat_workload_attribution",
                "path_volume",
            ],
        ),
        ("basic", "C", "basic-with-inventory", [], []),
        ("basic", "A", "basic-with-inventory", [], []),
        ("enhanced", "C", "enhanced", [], []),
        ("full", "C", "full", [], []),
        (
            "full",
            "D",
            "full",
            ["endpoint_effectiveness"],
            ["dependency_view", "gateway_inventory", "inter_vpc_cross_region", "nat_scoped_analysis"],
        ),
        (
            "enhanced",
            "D",
            "enhanced",
            ["endpoint_effectiveness"],
            [
                "aws_service_reach",
                "dependency_view",
                "gateway_inventory",
                "inter_vpc_cross_region",
                "nat_scoped_analysis",
                "path_volume",
            ],
        ),
    ],
)
def test_e1_tier_assignment(estates, tier, provider, expected_tier, unavailable, inferred):
    from network_flow_insight.demo.duck import DuckDBEngine

    fields = list(DuckDBEngine(estates[tier].s3_root, "nfi", "t").scheme.fields)
    out = assign_tier.assign_tier(fields, provider)
    assert out["tier"] == expected_tier
    assert out["unavailable_sections"] == sorted(unavailable)
    assert out["inferred_sections"] == sorted(inferred)
    if tier != "full":
        rec = out["upgrade_recommendation"]
        assert "${traffic-path}" in rec["custom_format"] and rec["delivery_options"]
    else:
        assert out["upgrade_recommendation"] is None


def test_e1_missing_required_fields_is_an_error():
    assert "error" in assign_tier.assign_tier(["srcaddr"], "C")


# ---------------------------------------------------------------------------------- E2


def test_e2_missing_account_is_listed_and_excluded(make_analysis):
    a, est = make_analysis("full", table_accounts=[E.ACCT_A])
    f = a.describe(*B, compare_previous=False)
    integ = f["integrity"]
    assert integ["missing_accounts"] == [E.ACCT_B]
    assert len(integ["missing_partitions"]) == 7
    assert integ["excluded_from_totals"] and integ["caution"]
    assert integ["accounts_in_data"] == [E.ACCT_A]
    # the second account's traffic is excluded from totals
    gt = est.truth["by_window"]["B"]
    igw = sum(
        v["c2s"] + v["s2c"]
        for ex in est.truth["exchanges"]
        if ex["kind"] == "internet-gateway"
        for d, v in ex["days"].items()
        if d >= B[0]
    )
    # w1 -> w4 (TGW) is normally counted at w1 (c2s) and w4 (s2c). With account B invisible, w4's interface logs
    # nothing, so its response is counted when it reaches w1 and no bytes of the exchange are lost.
    assert f["path_volume"]["by_path"]["total"]["bytes"] == gt["total_bytes"] - igw
    assert any("cannot see" in c for c in f["cautions"])


def test_e2_skipdata_share_and_caution(make_analysis):
    s = Settings(aws_region=E.REGION, skipdata_threshold=0.005)
    a, est = make_analysis("full", settings=s)
    f = a.describe(*B, compare_previous=False)
    ls = f["integrity"]["log_status"]
    gt = est.truth["by_window"]["B"]
    assert ls["skipdata_records"] == gt["skipdata_records"] == 20
    assert ls["total_records"] == gt["total_records"]
    assert ls["skipdata_share_pct"] == round(20 / gt["total_records"] * 100, 2)
    assert ls["caution"] is True
    assert any("SKIPDATA" in c for c in f["cautions"])
    a2, _ = make_analysis("full")
    assert a2.describe(*B, compare_previous=False)["integrity"]["log_status"]["caution"] is False


# ---------------------------------------------------------------------------------- E4


@pytest.mark.parametrize(
    "ratio, expected",
    [
        (1.0, "ok"),
        (1.04, "ok"),
        (0.96, "ok"),
        (2.0, "both-legs-counted"),
        (1.9, "both-legs-counted"),
        (1.4, "above"),
        (3.5, "above"),
        (0.5, "below"),
        (None, "no-data"),
    ],
)
def test_e4_diagnose_ratio(ratio, expected):
    assert diagnose_ratio(ratio, 0.05) == expected


def _legs(a):
    inv = a.b.inventory
    return _rows(a), sorted(inv.nat_addresses()), inv.nat_interface_ids()


def test_e4_planted_diagnoses_on_every_available_rung(make_analysis):
    a, est = make_analysis("full")
    rows, addrs, ifaces = _legs(a)
    gt = est.truth["by_window"]["B"]
    true_total = gt["nat_out_bytes"] + gt["nat_in_bytes"]
    metrics = {"nat-0001": {"kind": "nat", "comparable_bytes": true_total, "metrics": {}}}
    scenarios = {}
    # correct scoping
    scenarios["ok"] = nat_scope.nat_scope(rows, addrs, ifaces)["translated"]["total_bytes"]
    # both legs counted: every record on the NAT interface
    scenarios["both-legs-counted"] = nat_scope.nat_scope(rows, addrs, ifaces)[
        "unscoped_interface_total_bytes"
    ]
    # incomplete: secondary address missing
    scenarios["below"] = nat_scope.nat_scope(rows, [E.NAT_IPS[0]], ifaces)["translated"]["total_bytes"]
    # leak: a workload address in the filter
    scenarios["above"] = nat_scope.nat_scope(rows, [*addrs, "10.10.1.5"], ifaces)["translated"]["total_bytes"]
    for expected, flow_total in scenarios.items():
        leg = nat_leg_check.nat_leg_check(
            rows,
            addrs
            if expected in ("ok", "both-legs-counted")
            else ([E.NAT_IPS[0]] if expected == "below" else [*addrs, "10.10.1.5"]),
            ifaces,
        )
        r = reconcile.reconcile(
            leg_check=leg,
            flow_by_gateway={"nat-0001": flow_total},
            metrics=metrics,
            reference={"category": "nat_processing", "bytes": true_total},
            flow_for_reference={"nat_processing": flow_total},
        )
        rungs = {x["rung"]: x for x in r["rungs"] if x["status"] == "used"}
        assert rungs[2]["diagnosis"] == expected, (expected, rungs[2]["ratio"])
        assert rungs[4]["diagnosis"] == expected
        if expected in ("ok", "below", "above"):
            assert rungs[1]["diagnosis"] == expected
        if expected == "ok":
            assert r["verdict"] == "reconciled" and r["show_shares"] and r["shares_caution"] is None
        else:
            assert r["shares_caution"]


def test_e4_metrics_absent_uses_leg_check_and_reference(make_analysis):
    a, est = make_analysis(
        "full",
        with_metrics=False,
        with_cur=False,
        reference={"category": "nat_processing", "bytes": 633_000_000, "scope": "nat-0001"},
    )
    f = a.describe(*B, compare_previous=False)
    r = f["reconciliation"]
    assert r["rungs_used"] == [1, 4]
    assert {x["rung"] for x in r["rungs_unavailable"]} == {2, 3}
    assert r["verdict"] == "reconciled"


def test_e4_no_rung_means_no_shares():
    r = reconcile.reconcile(leg_check=None)
    assert r["verdict"] == "unverified" and not r["show_shares"] and r["shares_caution"]


def test_e4_report_withholds_or_cautions_shares(make_analysis):
    from network_flow_insight.tools.render_report import render_report

    a, _ = make_analysis(
        "full",
        with_metrics=False,
        with_cur=False,
        reference={"category": "nat_processing", "bytes": 300_000_000},
    )
    f = a.describe(*B, compare_previous=False)
    assert f["reconciliation"]["verdict"] == "partially-reconciled"
    md = render_report(f)["report.md"]
    assert "Shares shown with a caution" in md


# ---------------------------------------------------------------------------------- E11


def test_e11_cur_agreement_and_account_set_mismatch(make_analysis):
    a, _ = make_analysis("full")
    r = a.describe(*B, compare_previous=False)["reconciliation"]
    cur = next(x for x in r["rungs"] if x["rung"] == 3)
    assert cur["status"] == "used" and cur["diagnosis"] == "ok"
    assert set(cur["by_category"]) == {"nat_processing", "internet_out", "regional"}
    assert all(v["ratio"] == 1.0 for v in cur["by_category"].values())
    assert not cur.get("account_set_mismatch")

    a2, _ = make_analysis("full", cur_accounts=[E.ACCT_A])
    cur2 = next(
        x for x in a2.describe(*B, compare_previous=False)["reconciliation"]["rungs"] if x["rung"] == 3
    )
    assert cur2["account_set"]["only_in_flow_data"] == [E.ACCT_B]
    assert cur2["account_set_mismatch"] is True
    assert "account sets differ" in cur2["explanation"]


# ---------------------------------------------------------------------------------- E4a


def test_e4a_providers_a_and_c_agree_and_d_is_inferred(make_analysis, estates):
    from tests.unit.fakes import FakeSession

    est = estates["full"]
    doc = json.loads(est.inventory_path.read_text())
    from network_flow_insight.core.inventory import ec2

    collected = ec2.collect(FakeSession(doc), [E.REGION, E.OTHER_REGION], account_id=E.ACCT_A)
    inv_a = Inventory(collected)
    inv_c = Inventory(doc)
    a, _ = make_analysis("full")
    rows = _rows(a)
    ca = classify_path.classify_path(rows, inv_a)["rows"]
    cc = classify_path.classify_path(rows, inv_c)["rows"]
    # provider A is built from one account's EC2 view; the fixture's second account is invisible to it,
    # so compare on interfaces both providers know.
    known = set(inv_a.interfaces)

    def key(r):
        return (
            r["day"],
            r["interface_id"],
            r["srcaddr"],
            r["dstaddr"],
            r["srcport"],
            r["dstport"],
            r["action"],
        )

    pa = {key(r): r["path_class"] for r in ca if r["interface_id"] in known}
    pc = {key(r): r["path_class"] for r in cc if r["interface_id"] in known}
    assert pa and pa == pc
    # and the counting decision agrees wherever the peer is also known to provider A
    ka = {
        key(r): r["counted"]
        for r in ca
        if r["interface_id"] in known and "10.20.1.4" not in (r["srcaddr"], r["dstaddr"])
    }
    kc = {
        key(r): r["counted"]
        for r in cc
        if r["interface_id"] in known and "10.20.1.4" not in (r["srcaddr"], r["dstaddr"])
    }
    assert ka == kc


def test_e4a_provider_d_detects_forwarding_interfaces(make_analysis):
    a, _ = make_analysis("basic", inventory=False)
    f = a.describe(*B, compare_previous=False)
    det = f["inventory"]["detection"]["interfaces"]
    assert det["eni-0nat1"]["role_guess"] == "nat-gateway"
    assert det["eni-0nat1"]["method"] == "inferred"
    assert set(det["eni-0nat1"]["nat_addresses_guess"]) == set(E.NAT_IPS)
    # basic format: no pkt-* fields to confirm the workload leg, so the guess is medium confidence
    assert det["eni-0nat1"]["confidence"] == "medium"
    for iid in ("eni-0w1", "eni-0w2", "eni-0w3", "eni-0w4", "eni-0w5"):
        assert det[iid]["role_guess"] == "workload"
    assert f["tier"]["tier"] == "basic-no-inventory"
    assert f["meta"]["inventory_provider"] == "D"
    assert any("inferred" in c for c in f["cautions"])
    # NAT translated bytes are still found, and labelled inferred
    gt = a.windows[B]
    assert f["nat"]["inferred"] is True
    assert f["nat"]["scope"]["translated"]["total_bytes"] == 633_000_000
    assert gt.classified


def test_e4a_provider_d_forwarding_roles_include_transit_style_interface():
    rows = []
    for i in range(30):
        rows.append(
            {
                "interface_id": "eni-tgw",
                "srcaddr": f"10.1.{i}.5",
                "dstaddr": f"10.2.{i}.9",
                "bytes": 100,
                "records": 1,
                "log_status": "OK",
            }
        )
    out = detect_forwarding_interfaces.detect_forwarding_interfaces(rows)
    assert out["interfaces"]["eni-tgw"]["role_guess"] == "transit-gateway-or-appliance"


# ---------------------------------------------------------------------------------- E4b


def test_e4b_pairing_matches_ground_truth(full_findings):
    a, est, _f = full_findings
    convs = {
        (c["client"], c["server"], c["port"], c["path_class"]): c
        for c in a.windows[B].conversations
        if c["action"] == "ACCEPT"
    }
    for gt in est.truth["by_window"]["B"]["conversations"]:
        if gt["ambiguous"]:
            continue
        c = convs[(gt["client"], gt["server"], gt["port"], gt["path"])]
        assert (c["c2s_bytes"], c["s2c_bytes"]) == (gt["c2s"], gt["s2c"]), gt["id"]
        assert not c["ambiguous"]
    amb = [g for g in est.truth["by_window"]["B"]["conversations"] if g["ambiguous"]][0]
    hit = [c for c in convs.values() if c["ambiguous"]]
    assert len(hit) == 1 and hit[0]["total_bytes"] == amb["c2s"] + amb["s2c"]
    assert hit[0]["ambiguity"] == "both ports ephemeral"
    assert len(convs) == len(est.truth["by_window"]["B"]["conversations"])


# ---------------------------------------------------------------------------------- E5


def test_e5_classification(estates):
    est = estates["full"]
    inv = Inventory(json.loads(est.inventory_path.read_text()))
    ranges = IpRanges(json.loads(est.ip_ranges_path.read_text()))
    from network_flow_insight.core.intent_schema import load_intent

    intent = load_intent(est.intent_path)
    ips = [
        E.S3_LOCAL[0],
        E.S3_REMOTE_REGION,
        E.DDB_PUBLIC[0],
        E.EC2_ONLY,
        E.AMAZON_ONLY,
        E.ONPREM,
        E.INTERNET["a"],
        "10.10.2.7",
        "10.30.0.5",
        "10.10.1.200",
        "10.99.0.1",
        "198.18.99.9",
    ]
    out = classify_destination.classify_destination(ips, inv, intent, ranges, home_region=E.REGION)
    assert (out[E.S3_LOCAL[0]]["bucket"], out[E.S3_LOCAL[0]]["service"]) == ("aws-service", "S3")
    assert (
        out[E.S3_REMOTE_REGION]["cross_region"] is True and out[E.S3_REMOTE_REGION]["region"] == "us-east-1"
    )
    assert out[E.DDB_PUBLIC[0]]["service"] == "DYNAMODB"
    assert out[E.EC2_ONLY]["bucket"] == "aws-hosted-unverified"
    assert out[E.AMAZON_ONLY]["bucket"] == "aws-hosted-unverified"
    assert out[E.ONPREM]["bucket"] == "named-network" and out[E.ONPREM]["name"] == "on-prem-dc1"
    assert out[E.INTERNET["a"]]["bucket"] == "other-internet"
    assert out["10.10.2.7"]["bucket"] == "own-vpc" and out["10.30.0.5"]["cross_region"] is True
    assert (out["10.10.1.200"]["bucket"], out["10.10.1.200"]["service"]) == ("aws-service", "DYNAMODB")
    assert out["10.99.0.1"]["bucket"] == "private-unnamed"
    assert out["198.18.99.9"]["bucket"] == "aws-hosted-unverified"  # only the broad AMAZON /15 matches
    named = classify_destination.classify_destination(
        [E.AMAZON_ONLY, E.EC2_ONLY],
        inv,
        intent,
        ranges,
        home_region=E.REGION,
        resolver_names=json.loads(est.resolver_path.read_text()),
    )
    assert named[E.AMAZON_ONLY]["name"].startswith("queue.example-service")
    assert named[E.AMAZON_ONLY]["bucket"] == "aws-hosted-unverified"
    assert named[E.EC2_ONLY]["name"] == ""


def test_e5_most_specific_match_wins():
    doc = {
        "prefixes": [
            {"ip_prefix": "52.0.0.0/8", "region": "us-east-1", "service": "AMAZON"},
            {"ip_prefix": "52.95.0.0/16", "region": "us-east-1", "service": "S3"},
            {"ip_prefix": "52.95.1.0/24", "region": "us-east-1", "service": "EC2"},
        ]
    }
    r = IpRanges(doc)
    assert r.lookup("52.95.9.9").specific_services == ("S3",)
    assert r.lookup("52.95.1.9").specific_services == ()
    assert r.lookup("1.2.3.4") is None


# ---------------------------------------------------------------------------------- E6


def test_e6_endpoint_effectiveness_volumes(full_findings):
    _a, est, f = full_findings
    ee = f["endpoint_effectiveness"]

    def gt_bytes(ex_id):
        ex = next(e for e in est.truth["exchanges"] if e["id"] == ex_id)
        return sum(v["c2s"] + v["s2c"] for d, v in ex["days"].items() if B[0] <= d <= B[1])

    ie = ee["interface_endpoint_findings"]
    assert [x["endpoint_id"] for x in ie] == ["vpce-ddb"]
    assert ie[0]["bytes_on_nat"] == gt_bytes("DDB-nat") + gt_bytes("DDB-nat-B")
    gw = {(x["subnet_id"], x["service"]): x["bytes_on_nat"] for x in ee["missing_gateway_route_findings"]}
    assert gw[("subnet-app-a", "S3")] == gt_bytes("S3-nat")
    assert ("subnet-app-b", "S3") not in gw  # app-b has the route
    xr = ee["cross_region_findings"]
    assert xr[0]["service"] == "S3" and xr[0]["bytes_on_nat"] == gt_bytes("S3-xr")
    assert xr[0]["destination_region"] == "us-east-1"


def test_unsettled_window_is_built_under_a_version_and_flagged_provisional(make_analysis, monkeypatch):
    from datetime import UTC, datetime

    import network_flow_insight.analysis as analysis_mod

    # Twenty minutes after the end of the window's last day: records may still be arriving.
    monkeypatch.setattr(analysis_mod, "_utcnow", lambda: datetime.fromisoformat(f"{B[1]}T23:59:00+00:00").replace(tzinfo=UTC))
    a, est = make_analysis("full")
    f = a.describe(*B, compare_previous=False)
    assert f["meta"]["window_settled"] is False
    from network_flow_insight.core.aggregate import aggregate_table_name

    base = aggregate_table_name(*B, a.b.scheme.qualified)
    assert f["meta"]["aggregate_table"].split(".")[-1].startswith(base + "_b")
    assert any("has not settled" in c for c in f["cautions"])
    # figures are unaffected by the versioned name
    gt = est.truth["by_window"]["B"]
    assert f["nat"]["scope"]["translated"]["total_bytes"] == gt["nat_out_bytes"] + gt["nat_in_bytes"]
