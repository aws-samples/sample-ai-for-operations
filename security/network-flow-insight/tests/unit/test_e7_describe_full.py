# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""E7 and E3: describe mode on the Full fixture equals ground truth to the byte."""

from datetime import date

from network_flow_insight.demo import estate as E
from network_flow_insight.tools.render_report import render_report


def test_path_volumes_equal_ground_truth(full_findings):
    _a, est, f = full_findings
    gt = est.truth["by_window"]["B"]
    got = {r["path_class"]: r["bytes"] for r in f["path_volume"]["by_path"]["rows"]}
    assert got == gt["path_bytes"]
    assert f["path_volume"]["by_path"]["total"]["bytes"] == gt["total_bytes"]
    assert f["path_volume"]["counted_total_bytes"] == gt["total_bytes"]


def test_nat_scoping_matches_ground_truth_and_honours_both_addresses(full_findings):
    _a, est, f = full_findings
    gt = est.truth["by_window"]["B"]
    t = f["nat"]["scope"]["translated"]
    assert (t["out_bytes"], t["in_bytes"]) == (gt["nat_out_bytes"], gt["nat_in_bytes"])
    assert t["total_bytes"] == gt["nat_out_bytes"] + gt["nat_in_bytes"]
    by_addr = f["nat"]["scope"]["by_nat_address"]
    assert set(by_addr) == set(E.NAT_IPS) and all(v > 0 for v in by_addr.values())
    assert sum(by_addr.values()) == t["total_bytes"]
    # gateway-endpoint bytes are never part of the NAT total
    assert t["total_bytes"] == gt["path_bytes"]["internet-nat"]
    assert f["nat"]["leg_check"]["overall"]["ratio"] == 1.0


def test_internet_egress_by_bucket(full_findings):
    _a, est, f = full_findings
    gt = est.truth["by_window"]["B"]["dest_bucket_bytes"]
    got = {r["dest_bucket"]: r["bytes"] for r in f["internet_egress"]["by_bucket"]["rows"]}
    nat_igw_buckets = {}
    for ex in est.truth["exchanges"]:
        if ex["expected_path"] in ("internet-nat", "internet-igw"):
            b = sum(v["c2s"] + v["s2c"] for d, v in ex["days"].items() if "2026-03-02" <= d <= "2026-03-08")
            nat_igw_buckets[ex["expected_bucket"]] = nat_igw_buckets.get(ex["expected_bucket"], 0) + b
    assert got == nat_igw_buckets
    assert gt["aws-service"] > 0


def test_time_profile_and_concentration(full_findings):
    _a, est, f = full_findings
    gt = est.truth["by_window"]["B"]
    series = {s["day"]: s["bytes"] for s in f["time_profile"]["series"]}
    assert series == gt["per_day"]
    peak = max(gt["per_day"].items(), key=lambda kv: (kv[1], kv[0]))
    assert (f["time_profile"]["peak_day"]["day"], f["time_profile"]["peak_day"]["bytes"]) == peak
    wk = [b for d, b in gt["per_day"].items() if date.fromisoformat(d).weekday() < 5]
    we = [b for d, b in gt["per_day"].items() if date.fromisoformat(d).weekday() >= 5]
    assert f["time_profile"]["weekday_mean_bytes"] == sum(wk) // len(wk)
    assert f["time_profile"]["weekend_mean_bytes"] == sum(we) // len(we)
    hours = gt["hour_bytes"]
    ph = max(hours.items(), key=lambda kv: (kv[1], kv[0]))
    got = f["time_profile"]["peak_hour_of_window"]
    assert got["bytes"] == ph[1]
    by_client = gt["bytes_by_client"]
    top = max(by_client.items(), key=lambda kv: (kv[1], kv[0]))
    assert f["concentration"]["by_workload"]["rows"][0]["bytes"] == top[1]
    assert f["concentration"]["by_account"]["total"] == gt["total_bytes"]


def test_rejected_flows(full_findings):
    _a, est, f = full_findings
    gt = est.truth["by_window"]["B"]
    assert f["rejected"]["total_bytes"] == gt["rejected_bytes"]
    assert f["rejected"]["records"] == gt["rejected_records"]


def test_change_versus_previous_window(full_findings):
    _a, est, f = full_findings
    a, b = est.truth["by_window"]["A"], est.truth["by_window"]["B"]
    t = f["change"]["by_path"]["totals"]
    assert (t["current"], t["previous"]) == (b["total_bytes"], a["total_bytes"])
    new = {(r["server"]) for r in f["change"]["by_conversation"]["new"]}
    gone = {(r["server"]) for r in f["change"]["by_conversation"]["gone"]}
    assert E.INTERNET["new"] in new and E.INTERNET["gone"] in gone


def test_every_section_present_and_options_cite_flows_and_rates(full_findings):
    _a, _est, f = full_findings
    art = render_report(f)
    md = art["report.md"]
    for heading in (
        "Coverage and integrity",
        "Volume by path class",
        "Internet egress",
        "AWS services",
        "Inter-VPC",
        "NAT gateway traffic",
        "Concentration",
        "Time profile",
        "Gateway inventory",
        "Rejected flows",
        "What changed",
        "Dependency view",
        "Reconciliation",
        "Architecture options",
        "Methodology",
        "Blind spots",
        "Reproducibility",
    ):
        assert heading in md
    assert f["options"]["options"], "options expected on the planted fixture"
    for opt in f["options"]["options"]:
        assert opt["justifying_flows_bytes"] > 0
        assert opt["current_rate"]["per_gb"] is not None
    assert "data/edges.csv" in art and "data/series.csv" in art
    assert f["headlines"] and len(f["headlines"]) <= 5
    # reproducibility: every query has an execution ID
    assert all(q["execution_id"] for q in f["queries"] if not q["skipped"])


def test_one_raw_scan_per_window(full_findings):
    a, _est, f = full_findings
    raw = [q for q in f["queries"] if "build aggregate" in q["label"]]
    # current window plus the previous window used for the comparison
    assert len(raw) == 2
    assert not any(q["label"] == "raw query" for q in f["queries"])
    assert a.b.engine.gauge.summary()["skipped"] == 0
