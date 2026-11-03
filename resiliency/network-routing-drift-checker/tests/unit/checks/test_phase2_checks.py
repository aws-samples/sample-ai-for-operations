# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Phase 2 checks: TGW isolation (2.2), DX redundancy (2.3), hybrid path (2.4)."""

from drift_core.checks import EvaluationContext, check2_tgw, check4_redundancy, check6_hybrid_path
from tests.fixtures import snapshots as fx

MATRIX = {"prod": ["prod", "shared"], "dev": ["dev", "shared"], "shared": ["dev", "prod", "shared"]}
GW = "00000001-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def ctx(regions, intent, cloudwan=None, not_evaluated=()):
    return EvaluationContext(cloudwan=cloudwan, regions=regions, intent=intent,
                             regions_not_evaluated=frozenset(not_evaluated))


# ── 2.2 TGW isolation ────────────────────────────────────────────────────────

def iso_region():
    return fx.region(
        route_tables=[
            fx.tgw_table("tgw-rtb-0prd", "prod", [fx.tgw_route("10.1.0.0/16", "tgw-attach-0prd"),
                                                  fx.tgw_route("10.3.0.0/16", "tgw-attach-0shr")]),
            fx.tgw_table("tgw-rtb-0dev", "dev", [fx.tgw_route("10.2.0.0/16", "tgw-attach-0dev")]),
            fx.tgw_table("tgw-rtb-0shr", "shared", []),
        ],
        attachments=[fx.tgw_attachment("tgw-attach-0prd", "prod", "tgw-rtb-0prd"),
                     fx.tgw_attachment("tgw-attach-0dev", "dev", "tgw-rtb-0dev"),
                     fx.tgw_attachment("tgw-attach-0shr", "shared", "tgw-rtb-0shr")])


def run_iso(region, matrix=MATRIX):
    return check2_tgw.run(ctx({"eu-central-1": region}, {"tgw_isolation": matrix}))


def test_tgw_isolation_no_drift_with_shared_and_self():
    assert run_iso(iso_region()) == []


def test_tgw_dev_route_in_prod_is_leak_one_per_prefix():
    r = iso_region()
    r["route_tables"][0]["routes"] += [fx.tgw_route("10.2.0.0/16", "tgw-attach-0dev"),
                                       fx.tgw_route("10.2.9.0/24", "tgw-attach-0dev"),
                                       fx.tgw_route("10.2.8.0/24", "tgw-attach-0dev", state="blackhole")]
    out = run_iso(r)
    assert [f.kind for f in out] == ["tgw-prefix-leak", "tgw-prefix-leak"]
    assert {f.context["prefix"] for f in out} == {"10.2.0.0/16", "10.2.9.0/24"}
    assert out[0].observed == {"source_domain": ["dev"]} and out[0].context["matrix_key"] == "prod"


def test_tgw_matrix_keyed_by_route_table_id_and_untagged_source_uses_its_table():
    r = iso_region()
    r["route_tables"][0]["tags"] = {}
    r["attachments"][1]["tags"] = {}  # dev attachment untagged -> its table tgw-rtb-0dev (tag dev)
    r["route_tables"][0]["routes"].append(fx.tgw_route("10.2.0.0/16", "tgw-attach-0dev"))
    out = run_iso(r, {"tgw-rtb-0prd": ["shared"]})
    assert [f.context["source_attachment"] for f in out] == ["tgw-attach-0prd", "tgw-attach-0dev"] or \
        sorted(f.context["source_attachment"] for f in out) == ["tgw-attach-0dev", "tgw-attach-0prd"]
    # tgw-attach-0prd (tag prod) is not 'self' for an ID-keyed table whose tag was removed -> also a leak


def test_tgw_unnamed_table_and_unclassifiable_source_skipped():
    r = iso_region()
    r["route_tables"][2]["routes"].append(fx.tgw_route("10.9.0.0/16", "tgw-attach-0zzz"))
    r["route_tables"][0]["routes"].append(fx.tgw_route("10.9.0.0/16", "tgw-attach-0zzz"))  # unknown attachment
    assert run_iso(r, {"prod": ["prod", "shared"]}) == []
    assert check2_tgw.run(ctx({"eu-central-1": r}, None)) == []


# ── 2.3 DX redundancy ────────────────────────────────────────────────────────

def dx_region(*vifs):
    return fx.region(vifs=list(vifs))


PAIR = {"dx_redundancy_pairs": [{"name": "site-a", "members": ["dxvif-0001", "dxvif-0002"]}]}


def kinds(out):
    return sorted(f.kind for f in out)


def test_redundancy_healthy_pair_no_findings():
    assert check4_redundancy.run(ctx({"eu-central-1": dx_region(fx.vif("dxvif-0001"), fx.vif("dxvif-0002"))},
                                     PAIR)) == []


def test_redundancy_member_down_and_bgp_down():
    r = dx_region(fx.vif("dxvif-0001", state="down"), fx.vif("dxvif-0002", bgp="down"))
    out = check4_redundancy.run(ctx({"eu-central-1": r}, PAIR))
    assert kinds(out) == ["redundancy-bgp-down", "redundancy-member-down", "redundancy-pair-down"]


def test_redundancy_down_vif_does_not_also_report_bgp():
    r = dx_region(fx.vif("dxvif-0001", state="down", bgp="down"), fx.vif("dxvif-0002"))
    assert kinds(check4_redundancy.run(ctx({"eu-central-1": r}, PAIR))) == ["redundancy-member-down"]


def test_redundancy_member_missing_is_drift_not_file_error():
    out = check4_redundancy.run(ctx({"eu-central-1": dx_region(fx.vif("dxvif-0001"))}, PAIR))
    assert kinds(out) == ["redundancy-member-missing"] and out[0].severity == "drift"


def test_redundancy_both_missing_pair_down():
    assert kinds(check4_redundancy.run(ctx({"eu-central-1": dx_region()}, PAIR))) == [
        "redundancy-member-missing", "redundancy-member-missing", "redundancy-pair-down"]


def test_redundancy_missing_while_region_not_evaluated_is_unverified():
    out = check4_redundancy.run(ctx({"eu-central-1": dx_region(fx.vif("dxvif-0001"))}, PAIR,
                                    not_evaluated=("eu-west-1",)))
    assert kinds(out) == ["redundancy-member-unverified"] and out[0].severity == "system"


# ── 2.4 hybrid path ──────────────────────────────────────────────────────────

def dx_route(prefix, region_vif_gw=GW):
    return fx.tgw_route(prefix, "tgw-attach-0dxg", resource_type="direct-connect-gateway", resource_id=region_vif_gw)


def hp(**path):
    return {"hybrid_paths": [{"prefix": "192.168.0.0/16", **path}]}


def hybrid_regions():
    return {
        "eu-central-1": fx.region("eu-central-1", route_tables=[fx.tgw_table("tgw-rtb-0aaa", "shared",
                                                                             [dx_route("192.168.0.0/16")])],
                                  vifs=[fx.vif("dxvif-0001", dxgw_id=GW)]),
        "eu-west-1": fx.region("eu-west-1", route_tables=[fx.tgw_table("tgw-rtb-0bbb", "shared", [
            fx.tgw_route("192.168.0.0/16", "tgw-attach-0per", resource_type="peering", resource_id="tgw-0peer")])]),
    }


def test_hybrid_clean_exit_and_preferred_via_vif_dxgw():
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(exit_region="eu-central-1", preferred="dxvif-0001")))
    assert out == []  # peering next hop in eu-west-1 is not judged for exit


def test_hybrid_prefix_not_found_and_unverified():
    regions = hybrid_regions()
    for r in regions.values():
        r["route_tables"][0]["routes"] = []
    assert kinds(check6_hybrid_path.run(ctx(regions, hp(exit_region="eu-central-1")))) == [
        "hybrid-path-prefix-not-found"]
    out = check6_hybrid_path.run(ctx(regions, hp(exit_region="eu-central-1"), not_evaluated=("us-east-1",)))
    assert kinds(out) == ["hybrid-path-unverified"] and out[0].severity == "system"


def test_hybrid_wrong_exit_region_tgw_and_cloudwan():
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(exit_region="eu-west-1")))
    assert kinds(out) == ["hybrid-path-wrong-exit-region"] and out[0].region == "eu-central-1"
    cw = fx.clean_cloudwan()
    cw["route_tables"][0]["routes"] = [fx.cw_route("192.168.0.0/16", "hybrid", "attachment-0hyb")]
    out = check6_hybrid_path.run(ctx({}, hp(exit_region="eu-west-1"), cloudwan=cw))
    assert kinds(out) == ["hybrid-path-wrong-exit-region"] and out[0].context["core_network_id"] == fx.CORE


def test_hybrid_not_preferred_only_in_preferred_region():
    regions = hybrid_regions()
    regions["eu-central-1"]["route_tables"][0]["routes"] = [fx.tgw_route("192.168.0.0/16", "tgw-attach-0vpn",
                                                                         resource_type="vpn", resource_id="vpn-01")]
    out = check6_hybrid_path.run(ctx(regions, hp(preferred="dxvif-0001")))
    assert kinds(out) == ["hybrid-path-not-preferred"] and out[0].region == "eu-central-1"


def test_hybrid_backup_installed_unverifiable_and_absent():
    regions = hybrid_regions()
    regions["eu-central-1"]["route_tables"][0]["routes"][0]["attachments"].append(
        {"attachment_id": "tgw-attach-0vpn", "resource_type": "vpn", "resource_id": "vpn-01"})
    assert check6_hybrid_path.run(ctx(regions, hp(backup="vpn-01"))) == []  # in the installed (ECMP) set
    regions = hybrid_regions()
    regions["eu-central-1"]["vpn_connections"] = [{"vpn_id": "vpn-01", "state": "available", "tunnels": 2,
                                                   "tunnels_up": 1}]
    out = check6_hybrid_path.run(ctx(regions, hp(backup="vpn-01")))
    assert kinds(out) == ["hybrid-path-backup-unverifiable"] and out[0].severity == "informational"
    regions["eu-central-1"]["vpn_connections"][0]["tunnels_up"] = 0
    out = check6_hybrid_path.run(ctx(regions, hp(backup="vpn-01")))
    assert kinds(out) == ["hybrid-path-backup-absent"] and "0 tunnel(s) up" in out[0].message
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(backup="dxvif-0009")))
    assert kinds(out) == ["hybrid-path-backup-absent"]
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(backup="dxvif-0009"), not_evaluated=("us-east-1",)))
    assert kinds(out) == ["hybrid-path-unverified"]


def test_hybrid_backup_cloudwan_attachment_and_dxgw():
    cw = fx.clean_cloudwan()  # already installs 192.168.0.0/16 via attachment-0hyb
    assert check6_hybrid_path.run(ctx(hybrid_regions(), hp(backup="attachment-0hyb"), cloudwan=cw)) == []
    cw["route_tables"][0]["routes"] = [r for r in cw["route_tables"][0]["routes"]
                                       if r["prefix"] != "192.168.0.0/16"]  # standby: not installed
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(backup="attachment-0hyb"), cloudwan=cw))
    assert kinds(out) == ["hybrid-path-backup-unverifiable"]
    out = check6_hybrid_path.run(ctx(hybrid_regions(), hp(backup="attachment-0hyb")))
    assert kinds(out) == ["hybrid-path-unverified"]  # Cloud WAN not evaluated
    regions = hybrid_regions()
    regions["eu-central-1"]["dx_gateway_associations"] = [{"association_id": "a", "dxgw_id": "dxgw-x",
                                                           "state": "associated"}]
    assert kinds(check6_hybrid_path.run(ctx(regions, hp(backup="dxgw-x")))) == ["hybrid-path-backup-unverifiable"]
    assert check6_hybrid_path.run(ctx(regions, None)) == []
