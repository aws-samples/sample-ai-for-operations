# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""NAT scoping, leg check, path labels and provider D on record shapes captured from a real NAT interface."""

from __future__ import annotations

import pytest

from network_flow_insight.core.inventory.model import Inventory
from network_flow_insight.tools import classify_path, detect_forwarding_interfaces, nat_leg_check, nat_scope
from tests.fixtures import nat_real_rows as R

TRANSLATED = R.S3_OUT + R.S3_IN + 2 * R.NTP_BYTES
UNTRANSLATED = R.S3_OUT + R.S3_IN + 2 * R.NTP_BYTES
UNSOLICITED = R.SCANNER_BYTES  # accepted on the internet side, never translated or forwarded


def _inventory() -> Inventory:
    def iface(i, subnet, role, ips):
        return {"id": i, "account_id": R.ACCOUNT, "region": R.REGION, "vpc_id": R.VPC, "subnet_id": subnet,
                "az": "eu-west-2a", "role": role, "private_ips": ips, "description": ""}

    return Inventory(
        {
            "schema_version": 1,
            "source": "file",
            "vpcs": [{"id": R.VPC, "account_id": R.ACCOUNT, "region": R.REGION, "cidrs": ["10.0.0.0/16"]}],
            "subnets": [],
            "route_tables": [],
            "interfaces": [
                iface(R.NAT_ENI, R.NAT_SUBNET, "nat-gateway", [R.NAT_IP]),
                iface(R.WL_A_ENI, R.WL_A_SUBNET, "workload", [R.WL_A]),
                iface(R.WL_B_ENI, R.WL_B_SUBNET, "workload", [R.WL_B]),
            ],
            "nat_gateways": [{"id": R.NAT_ID, "vpc_id": R.VPC, "subnet_id": R.NAT_SUBNET,
                              "interface_ids": [R.NAT_ENI], "private_ips": [R.NAT_IP], "public_ips": []}],
            "endpoints": [],
            "prefix_lists": [],
        }
    )


@pytest.mark.parametrize("fmt", ["full", "basic"])
def test_every_nat_row_carries_the_nat_address_and_falls_in_one_leg(fmt):
    rows = R.nat_rows() if fmt == "full" else R.basic(R.nat_rows())
    legs = [nat_scope.nat_leg(r, {R.NAT_IP}) for r in rows]
    assert legs == ["untranslated", "translated", "translated", "untranslated"] * 2 + ["translated"]


@pytest.mark.parametrize("fmt", ["full", "basic"])
def test_nat_scope_counts_the_translated_leg_once(fmt):
    rows = R.nat_rows() if fmt == "full" else R.basic(R.nat_rows())
    s = nat_scope.nat_scope(rows, [R.NAT_IP], [R.NAT_ENI])
    assert s["translated"]["total_bytes"] == TRANSLATED
    assert s["translated"]["out_bytes"] == R.S3_OUT + R.NTP_BYTES
    assert s["translated"]["in_bytes"] == R.S3_IN + R.NTP_BYTES
    assert s["untranslated"]["total_bytes"] == UNTRANSLATED
    assert s["untranslated"]["out_bytes"] == R.S3_OUT + R.NTP_BYTES
    assert s["unmatched"]["total_bytes"] == 0
    assert (s["unsolicited"]["total_bytes"], s["unsolicited"]["records"]) == (UNSOLICITED, 1)
    assert s["unsolicited"]["top_sources"][0]["remote"] == R.SCANNER
    # remotes are the internet-side peers the workloads talked to, never the workloads or unsolicited sources
    assert {r["remote"] for r in s["remote_rows"]} == {R.S3_REMOTE, R.NTP_REMOTE}
    wl = {w["workload"]: w for w in s["by_workload"]}
    assert set(wl) == {R.WL_A, R.WL_B}
    assert (wl[R.WL_A]["out_bytes"], wl[R.WL_A]["in_bytes"]) == (R.S3_OUT, R.S3_IN)
    assert s["attribution_method"] == "untranslated-leg"


def test_nat_scope_pairs_workloads_with_their_real_remote_when_pkt_fields_exist():
    s = nat_scope.nat_scope(R.nat_rows(), [R.NAT_IP], [R.NAT_ENI])
    pairs = {(p["workload"], p["remote"]): p["total_bytes"] for p in s["by_workload_remote"]}
    assert pairs == {(R.WL_A, R.S3_REMOTE): R.S3_OUT + R.S3_IN, (R.WL_B, R.NTP_REMOTE): 2 * R.NTP_BYTES}
    assert nat_scope.nat_scope(R.basic(R.nat_rows()), [R.NAT_IP], [R.NAT_ENI])["by_workload_remote"] == []


def test_leg_check_is_near_one_on_real_shapes():
    leg = nat_leg_check.nat_leg_check(R.nat_rows(), [R.NAT_IP], [R.NAT_ENI])
    assert leg["overall"]["translated_bytes"] == TRANSLATED
    assert leg["overall"]["untranslated_bytes"] == UNTRANSLATED
    assert leg["overall"]["diagnosis"] == "ok"
    assert leg["overall"]["ratio"] == pytest.approx(1.0, abs=1e-6)


def test_leg_check_flags_a_missing_nat_address_as_below():
    leg = nat_leg_check.nat_leg_check(R.nat_rows(), ["10.0.0.99"], [R.NAT_ENI])
    assert leg["overall"]["unmatched_bytes"] == TRANSLATED + UNTRANSLATED + UNSOLICITED
    assert leg["overall"]["diagnosis"] == "below"


def test_internet_scans_of_the_nat_address_do_not_move_the_leg_check():
    # Seen on real data: about 430,000 probe records in an hour pushed the leg check to 1.08 when they were
    # counted as translated. The gateway's own metrics leave them out (BytesInFromDestination equals
    # BytesOutToSource exactly), so they are kept apart.
    flood = [{**R.nat_rows()[-1], "bytes": R.S3_IN // 2, "srcaddr": f"192.0.2.{i}"} for i in range(1, 3)]
    leg = nat_leg_check.nat_leg_check(R.nat_rows() + flood, [R.NAT_IP], [R.NAT_ENI])
    assert leg["overall"]["diagnosis"] == "ok" and leg["overall"]["ratio"] == pytest.approx(1.0, abs=1e-6)
    assert leg["overall"]["unsolicited_bytes"] == UNSOLICITED + 2 * (R.S3_IN // 2)


def test_return_traffic_is_solicited_even_after_port_normalisation():
    # In the aggregate the NAT's ephemeral port is stored as 0 on both legs; the remote's port stays.
    s = nat_scope.nat_scope(R.basic(R.nat_rows()), [R.NAT_IP], [R.NAT_ENI])
    assert s["translated"]["in_bytes"] == R.S3_IN + R.NTP_BYTES and s["unsolicited"]["total_bytes"] == UNSOLICITED


def test_classify_path_labels_both_legs_on_the_nat_interface():
    out = classify_path.classify_path(R.nat_rows(), _inventory())["rows"]
    labels = [r["path_class"] for r in out]
    assert labels == ["nat-untranslated-leg", "nat-translated-leg", "nat-translated-leg", "nat-untranslated-leg"] * 2 + [
        "nat-unsolicited-inbound"
    ]
    assert not any(r["counted"] for r in out)


@pytest.mark.parametrize("fmt", ["full", "basic"])
def test_provider_d_recognises_a_real_nat_interface(fmt):
    rows = R.nat_rows() + R.workload_rows()
    rows = rows if fmt == "full" else R.basic(rows)
    det = detect_forwarding_interfaces.detect_forwarding_interfaces(rows)["interfaces"]
    assert det[R.NAT_ENI]["role_guess"] == "nat-gateway"
    assert det[R.NAT_ENI]["nat_addresses_guess"] == [R.NAT_IP]
    assert det[R.NAT_ENI]["confidence"] == ("high" if fmt == "full" else "medium")
    assert det[R.WL_A_ENI]["role_guess"] == "workload"
    assert det[R.WL_B_ENI]["role_guess"] == "workload"


def test_provider_d_does_not_take_a_real_transit_gateway_attachment_for_a_workload():
    rows = R.nat_rows() + R.workload_rows() + R.tgw_rows()
    det = detect_forwarding_interfaces.detect_forwarding_interfaces(rows)["interfaces"]
    assert det[R.TGW_ENI]["role_guess"] == "transit-gateway-or-appliance"
    assert det[R.TGW_ENI]["owned_addresses"] == []
    assert det[R.NAT_ENI]["role_guess"] == "nat-gateway"


def _inventory_without_workload_a(extra_routes=(), prefix_lists=()) -> Inventory:
    """The workload's interface was deleted during the window; its subnet and route table remain."""
    inv = _inventory()
    base = {
        "schema_version": 1,
        "source": "file",
        "vpcs": [{"id": R.VPC, "account_id": R.ACCOUNT, "region": R.REGION, "cidrs": ["10.0.0.0/16"]}],
        "subnets": [
            {"id": R.WL_A_SUBNET, "vpc_id": R.VPC, "account_id": R.ACCOUNT, "region": R.REGION,
             "az": "eu-west-2a", "cidr": "10.0.1.0/24", "route_table_id": "rtb-0example0priva"},
        ],
        "route_tables": [
            {"id": "rtb-0example0priva", "vpc_id": R.VPC, "routes": [
                *extra_routes,
                {"destination": "10.0.0.0/16", "target_type": "local", "target_id": "local"},
                {"destination": "0.0.0.0/0", "target_type": "nat-gateway", "target_id": R.NAT_ID},
            ]},
        ],
        "interfaces": [i for i in inv.interfaces.values() if i["id"] != R.WL_A_ENI],
        "nat_gateways": [{"id": R.NAT_ID, "vpc_id": R.VPC, "subnet_id": R.NAT_SUBNET,
                          "interface_ids": [R.NAT_ENI], "private_ips": [R.NAT_IP], "public_ips": []}],
        "endpoints": [],
        "prefix_lists": list(prefix_lists),
    }
    return Inventory(base)


def test_deleted_interface_is_classified_from_the_records_subnet_and_counts_public_inbound():
    rows = [r for r in R.workload_rows() if r["interface_id"] == R.WL_A_ENI]
    out = classify_path.classify_path(rows, _inventory_without_workload_a())["rows"]
    by_dir = {r["direction"]: r for r in out}
    assert by_dir["out"]["path_class"] == by_dir["in"]["path_class"] == "internet-nat"
    assert by_dir["out"]["method"] == by_dir["in"]["method"] == "route-table"
    assert by_dir["out"]["counted"] and by_dir["in"]["counted"]


def test_deleted_interface_does_not_count_inbound_from_a_private_peer():
    row = {**R.workload_rows()[1], "srcaddr": R.WL_B, "pkt_srcaddr": R.WL_B}
    out = classify_path.classify_path([row], _inventory_without_workload_a())["rows"][0]
    assert out["direction"] == "in" and not out["counted"]


def test_traffic_path_1_agrees_with_intra_vpc_classification():
    # AWS logs traffic-path 1 ("through another resource in the same VPC") on workload-to-workload egress.
    row = {**R.workload_rows()[0], "dstaddr": R.WL_B, "pkt_dstaddr": R.WL_B, "dstport": 8080, "traffic_path": 1}
    res = classify_path.classify_path([row], _inventory())
    assert res["rows"][0]["path_class"].startswith("intra-vpc")
    assert res["traffic_path_crosscheck"] == {"agree": 1}


def test_crosscheck_explains_records_whose_traffic_path_disagrees_with_current_routes():
    # The record says it went through a resource in the VPC (NAT at the time); today's route table sends the
    # destination to a gateway endpoint (added during the window).
    inv = _inventory_without_workload_a(
        extra_routes=[{"prefix_list_id": "pl-0example0ddb", "target_type": "gateway-endpoint", "target_id": "vpce-0example"}],
        prefix_lists=[{"id": "pl-0example0ddb", "name": "ddb", "cidrs": ["198.51.100.0/24"]}],
    )
    row = R.workload_rows()[0]  # egress to S3_REMOTE, traffic-path 1
    res = classify_path.classify_path([row], inv)
    assert res["rows"][0]["path_class"] == "gateway-endpoint"
    assert res["traffic_path_crosscheck"]["disagree"] == 1
    d = res["traffic_path_disagreements"]
    assert d == [{"path_class": "gateway-endpoint", "traffic_path_class": "via-vpc-resource",
                  "subnet_id": R.WL_A_SUBNET, "records": 1, "bytes": R.S3_OUT}]


def test_inbound_from_a_known_workload_whose_interface_is_not_logged_is_counted_here():
    # Workload B is in the inventory, but its VPC's flow log is not in this table: nobody else counts its bytes.
    row = {**R.workload_rows()[1], "srcaddr": R.WL_B, "pkt_srcaddr": R.WL_B, "srcport": 8080, "dstport": 0}
    only_a = classify_path.classify_path([row], _inventory())["rows"][0]
    assert only_a["direction"] == "in" and only_a["counted"]
    # When B's interface does log in the window, its egress counts the bytes and A's inbound does not.
    b_egress = {**R.workload_rows()[2], "dstaddr": R.WL_A, "pkt_dstaddr": R.WL_A}
    both = classify_path.classify_path([row, b_egress], _inventory())["rows"]
    assert not both[0]["counted"] and both[1]["counted"]


def test_provider_d_spots_a_transit_gateway_attachment_in_the_default_format():
    # No pkt-* fields: the attachment's address is on all its records, and the workloads it talks to are logged
    # but never record that address (they record the real peer), so it relays rather than serves.
    rows = R.basic(R.nat_rows() + R.workload_rows() + R.tgw_rows() + R.tgw_workload_rows())
    det = detect_forwarding_interfaces.detect_forwarding_interfaces(rows)["interfaces"]
    assert det[R.TGW_ENI]["role_guess"] == "transit-gateway-or-appliance"
    assert det[R.TGW_ENI]["confidence"] == "medium"
    assert det[R.NAT_ENI]["role_guess"] == "nat-gateway"
    assert det[R.WL_A_ENI]["role_guess"] == "workload" and det[R.WL_B_ENI]["role_guess"] == "workload"


def test_provider_d_keeps_a_real_private_server_as_a_workload():
    # A server in the same VPC is recorded by its client's own interface, so it is not a relay.
    srv_eni, srv = "eni-0example000srv", "10.0.2.50"
    client = [
        {**R.workload_rows()[0], "dstaddr": srv, "dstport": 8080, "pkt_dstaddr": srv},
        {**R.workload_rows()[1], "srcaddr": srv, "srcport": 8080, "pkt_srcaddr": srv},
    ]
    server = [
        {**client[0], "interface_id": srv_eni},
        {**client[1], "interface_id": srv_eni},
    ]
    det = detect_forwarding_interfaces.detect_forwarding_interfaces(R.basic(client + server))["interfaces"]
    assert det[srv_eni]["role_guess"] == "workload"


def test_gateway_metrics_rung_names_skipdata_as_the_likely_cause_of_a_low_ratio():
    # Seen on real data: a NAT interface logged 31 SKIPDATA records in an hour (under 0.01% of its records) while
    # flow-derived bytes ran about 7% below the gateway's metrics.
    from network_flow_insight.tools import reconcile

    leg = nat_leg_check.nat_leg_check(R.nat_rows(), [R.NAT_IP], [R.NAT_ENI])
    metrics = {R.NAT_ID: {"kind": "nat", "metrics": {}, "comparable_bytes": int(TRANSLATED / 0.93)}}
    r = reconcile.reconcile(leg_check=leg, flow_by_gateway={R.NAT_ID: TRANSLATED}, metrics=metrics,
                            skipdata_by_gateway={R.NAT_ID: 31})
    rung2 = next(x for x in r["rungs"] if x["rung"] == 2)
    assert rung2["diagnosis"] == "below"
    assert rung2["per_gateway"][R.NAT_ID]["skipdata_records"] == 31
    assert "SKIPDATA" in rung2["explanation"] and "SKIPDATA" in r["shares_caution"]
    clean = reconcile.reconcile(leg_check=leg, flow_by_gateway={R.NAT_ID: TRANSLATED}, metrics=metrics)
    assert "SKIPDATA" not in next(x for x in clean["rungs"] if x["rung"] == 2)["explanation"]
