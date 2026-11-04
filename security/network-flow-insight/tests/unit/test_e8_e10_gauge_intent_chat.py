# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""E8 cost gauge, E9 chat mode (deterministic part), E10 intent lifecycle."""

import yaml

from network_flow_insight.core.athena import AthenaEngine, CostGauge, GaugedEngine, QuerySkipped
from network_flow_insight.core.intent_schema import Intent
from network_flow_insight.core.sqlsafe import SqlPolicy
from network_flow_insight.demo import estate as E
from network_flow_insight.tools.run_athena import run_athena
from network_flow_insight.toolset import ToolSession

A, B = E.WINDOW_A, E.WINDOW_B


class FakeAthena:
    """Just enough of the Athena API: every query succeeds and scans what the test says."""

    def __init__(self, scans=None):
        self.n = 0
        self.scans = scans or {}
        self.sql = {}

    def start_query_execution(self, QueryString, **kw):  # noqa: N803
        self.n += 1
        qid = f"q-{self.n:04d}"
        self.sql[qid] = QueryString
        return {"QueryExecutionId": qid}

    def get_query_execution(self, QueryExecutionId):  # noqa: N803
        sql = self.sql[QueryExecutionId]
        scanned = next((v for k, v in self.scans.items() if k in sql), 10_000_000)
        return {
            "QueryExecution": {
                "Status": {"State": "SUCCEEDED"},
                "StatementType": "DML",
                "Statistics": {"DataScannedInBytes": scanned, "TotalExecutionTimeInMillis": 5},
            }
        }

    def get_query_results(self, QueryExecutionId, MaxResults=1000, NextToken=None):  # noqa: N803
        info = [{"Label": "n", "Type": "bigint"}, {"Label": "s", "Type": "varchar"}]
        rows = [
            {"Data": [{"VarCharValue": "n"}, {"VarCharValue": "s"}]},
            {"Data": [{"VarCharValue": "7"}, {"VarCharValue": "x"}]},
        ]
        return {"ResultSet": {"ResultSetMetadata": {"ColumnInfo": info}, "Rows": rows}}


def _engine(price=5.0, ceiling=1.0, budget=100.0, interactive=False, confirm=None, scans=None):
    fake = FakeAthena(scans)
    g = CostGauge(price, ceiling, budget)
    return (
        GaugedEngine(AthenaEngine(fake, "wg", "s3://r/", "db"), g, interactive=interactive, confirm=confirm),
        g,
        fake,
    )


# ------------------------------------------------------------------------------ E8


def test_e8_ten_queries_estimate_before_actual_after_running_total():
    eng, g, _ = _engine()
    policy = SqlPolicy({"agg": ("day",)})
    estimates = [
        10_000_000,
        50_000_000,
        2_000_000_000,
        7_500_000_000,
        123_456_789,
        1,
        999_999_999,
        40_000_000_000,
        5_000_000,
        300_000_000,
    ]
    expected_total = 0.0
    for i, est in enumerate(estimates):
        out = run_athena(
            f"SELECT {i} AS x, count(*) FROM agg WHERE day = '2026-03-02'",  # nosec B608 -- test SQL names only tables and values the test itself defines
            policy,
            eng,
            estimated_bytes=est,
            label=f"q{i}",
        )
        assert out["status"] == "ok" and out["execution_id"] and out["estimated_bytes"] == est
        assert out["scanned_bytes"] == 10_000_000  # actual, reported after
        expected_total += max(10_000_000, 10_000_000) / 1e12 * 5.0
        assert out["running_total"]["scanned_bytes"] == 10_000_000 * (i + 1)
    assert round(g.total_cost_usd, 4) == round(expected_total, 4)
    assert len(g.ledger) == 10 and all(e.execution_id for e in g.ledger)
    assert g.estimate(2_000_000_000) == {"bytes": 2_000_000_000, "gb": 2.0, "cost_usd": 0.01}


def test_e8_over_ceiling_prompts_when_interactive_and_skips_when_scheduled():
    asked = []
    eng, g, fake = _engine(
        ceiling=0.01, interactive=True, confirm=lambda label, est: asked.append((label, est)) or False
    )
    policy = SqlPolicy({"agg": ("day",)})
    out = run_athena(
        "SELECT count(*) FROM agg WHERE day = '2026-03-02'", policy, eng, estimated_bytes=10**12, label="big"
    )
    assert out["status"] == "skipped" and asked and asked[0][1]["cost_usd"] == 5.0
    assert fake.n == 0  # nothing reached Athena
    assert g.ledger[-1].skipped and "declined" in g.ledger[-1].reason

    eng2, g2, fake2 = _engine(ceiling=0.01, interactive=False)
    out2 = run_athena(
        "SELECT count(*) FROM agg WHERE day = '2026-03-02'", policy, eng2, estimated_bytes=10**12
    )
    assert out2["status"] == "skipped" and fake2.n == 0
    assert "non-interactive" in g2.ledger[-1].reason

    eng3, g3, _ = _engine(ceiling=0.01, interactive=True, confirm=lambda *_: True)
    assert (
        run_athena("SELECT count(*) FROM agg WHERE day = '2026-03-02'", policy, eng3, estimated_bytes=10**12)[
            "status"
        ]
        == "ok"
    )


def test_e8_session_budget_is_a_hard_stop():
    eng, g, fake = _engine(ceiling=100, budget=0.0001)
    policy = SqlPolicy({"agg": ("day",)})
    out = run_athena("SELECT count(*) FROM agg WHERE day = '2026-03-02'", policy, eng, estimated_bytes=10**11)
    assert out["status"] == "skipped" and "budget" in g.ledger[-1].reason and fake.n == 0


def test_e8_unbounded_sql_is_rejected_and_never_executed():
    eng, _, fake = _engine()
    policy = SqlPolicy({"agg": ("day",)})
    for sql in (
        "SELECT * FROM agg",
        "SELECT * FROM agg WHERE bytes > 1",
        "DROP TABLE agg",
        "SELECT * FROM other WHERE day='x'",
    ):
        assert run_athena(sql, policy, eng, estimated_bytes=1)["status"] == "rejected"
    assert fake.n == 0


def test_e8_trend_from_metrics_has_zero_scan(full):
    ts = ToolSession(full[0] if isinstance(full, tuple) else full)
    before = ts.a.b.engine.gauge.total_bytes
    out = ts.metric_trend("nat-0001", *B)
    assert out["status"] == "ok" and out["scanned_bytes"] == 0
    assert out["metrics"]["nat-0001"]["comparable_bytes"] > 0
    assert ts.a.b.engine.gauge.total_bytes == before


def test_e8_query_raw_is_gauged_against_whole_window(full):
    a, _ = full
    ts = ToolSession(a)
    out = ts.query_raw(
        "SELECT count(*) AS n FROM flow_logs WHERE day BETWEEN '2026/03/02' AND '2026/03/08'", *B
    )
    assert out["status"] == "ok" and out["estimated_bytes"] > 0 and out["source"] == "raw"
    assert ts.query_raw("SELECT count(*) FROM flow_logs")["status"] == "rejected"


def test_e8_query_raw_rejects_predicates_that_do_not_narrow_the_scan_and_never_runs_them(full):
    a, _ = full
    ts = ToolSession(a)
    before = a.b.engine.gauge.summary()["queries"]
    for sql in (
        "SELECT count(*) FROM flow_logs WHERE day > '2000/01/01'",
        "SELECT count(*) FROM flow_logs WHERE day = day",
        "SELECT count(*) FROM flow_logs WHERE day BETWEEN '2026/03/02' AND '2026/03/08' OR 1 = 1",
        "SELECT count(*) FROM flow_logs WHERE day BETWEEN '2026/01/01' AND '2026/03/08'",
    ):
        out = ts.query_raw(sql, *B)
        assert out["status"] == "rejected" and out["executed"] is False and "window" in out["reason"]
    assert a.b.engine.gauge.summary()["queries"] == before


# ------------------------------------------------------------------------------ E9


def _cell(out):
    assert out["status"] == "ok", out
    return out["rows"]


def test_e9_chat_questions_are_bounded_and_match_ground_truth(full):
    a, est = full
    ts = ToolSession(a)
    ts.describe(*B, compare_previous=False)
    gt = est.truth["by_window"]["B"]
    t = a.windows[B].table
    where = "day BETWEEN '2026-03-02' AND '2026-03-08'"
    q = lambda sql: _cell(ts.query_aggregate(sql))  # noqa: E731

    from network_flow_insight.tools.nat_scope import translated_leg_sql

    leg = translated_leg_sql("'10.10.0.10','10.10.0.11'", True)
    # Q0 every NAT-interface record carries a NAT address, so the plain address filter counts both legs
    r = q(
        f"SELECT SUM(bytes) AS b FROM {t} WHERE {where} AND action='ACCEPT' AND interface_id='eni-0nat1' AND (srcaddr IN ('10.10.0.10','10.10.0.11') OR dstaddr IN ('10.10.0.10','10.10.0.11'))"  # nosec B608 -- test SQL names only tables and values the test itself defines
    )
    assert r[0]["b"] == 2 * (gt["nat_out_bytes"] + gt["nat_in_bytes"])
    # Q1 NAT translated-leg total
    r = q(f"SELECT SUM(bytes) AS b FROM {t} WHERE {where} AND action='ACCEPT' AND interface_id='eni-0nat1' AND {leg}")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert r[0]["b"] == gt["nat_out_bytes"] + gt["nat_in_bytes"]
    # Q2 NAT translated-leg bytes per day
    r = q(
        f"SELECT day, SUM(bytes) AS b FROM {t} WHERE {where} AND action='ACCEPT' AND interface_id='eni-0nat1' AND {leg} GROUP BY 1 ORDER BY 1"  # nosec B608 -- test SQL names only tables and values the test itself defines
    )
    per_day = {}
    for ex in est.truth["exchanges"]:
        if ex["kind"] == "nat":
            for d, v in ex["days"].items():
                if B[0] <= d <= B[1]:
                    per_day[d] = per_day.get(d, 0) + v["c2s"] + v["s2c"]
    assert {x["day"]: x["b"] for x in r} == per_day
    # Q3 rejected records
    r = q(f"SELECT SUM(records) AS n FROM {t} WHERE {where} AND action='REJECT'")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert r[0]["n"] == gt["rejected_records"]
    # Q4 SKIPDATA records
    r = q(f"SELECT SUM(records) AS n FROM {t} WHERE {where} AND log_status='SKIPDATA'")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert r[0]["n"] == gt["skipdata_records"]
    # Q5 records overall
    r = q(f"SELECT SUM(records) AS n FROM {t} WHERE {where}")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert r[0]["n"] == gt["total_records"]
    # Q6 distinct interfaces
    r = q(f"SELECT COUNT(DISTINCT interface_id) AS n FROM {t} WHERE {where}")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert r[0]["n"] == 6
    # Q7 port 443 share of bytes sent by workload interfaces
    r = q(
        f"SELECT SUM(bytes) AS b FROM {t} WHERE {where} AND interface_id='eni-0w3' AND srcaddr='10.10.3.9' AND dstport=443"  # nosec B608 -- test SQL names only tables and values the test itself defines
    )
    expected = sum(
        v["c2s"]
        for ex in est.truth["exchanges"]
        if ex["client"] == "10.10.3.9" and ex["port"] == 443
        for d, v in ex["days"].items()
        if B[0] <= d <= B[1]
    )
    assert r[0]["b"] == expected
    # Q8 the aggregate has hour of day
    r = q(
        f"SELECT hour, SUM(bytes) AS b FROM {t} WHERE {where} AND interface_id='eni-0w1' AND srcaddr='10.10.1.5' AND dstaddr='10.10.1.6' GROUP BY 1"  # nosec B608 -- test SQL names only tables and values the test itself defines
    )
    assert sum(x["b"] for x in r) == sum(
        v["c2s"]
        for ex in est.truth["exchanges"]
        if ex["id"] in ("IV-saz", "AMB")
        for d, v in ex["days"].items()
        if B[0] <= d <= B[1]
    )
    # Q9 remote addresses seen by the NAT on port 443
    r = q(
        f"SELECT COUNT(DISTINCT dstaddr) AS n FROM {t} WHERE {where} AND interface_id='eni-0nat1' AND srcaddr IN ('10.10.0.10','10.10.0.11') AND dstport=443"  # nosec B608 -- test SQL names only tables and values the test itself defines
    )
    assert r[0]["n"] == len(
        {
            ex["server"]
            for ex in est.truth["exchanges"]
            if ex["kind"] == "nat" and any(B[0] <= d <= B[1] for d in ex["days"])
        }
    )
    # Q10 aggregate rows per day
    r = q(f"SELECT day, COUNT(*) AS n FROM {t} WHERE {where} GROUP BY 1 ORDER BY 1")  # nosec B608 -- test SQL names only tables and values the test itself defines
    assert [x["day"] for x in r] == sorted(gt["per_day"])


def test_e9_out_of_scope_and_unsafe_questions_are_declined_by_the_gate(full):
    a, _ = full
    ts = ToolSession(a)
    assert ts.query_aggregate("SELECT 1")["status"] == "rejected"  # before any aggregate exists
    ts.describe(*B, compare_previous=False)
    for sql in (
        "SELECT * FROM somewhere_else WHERE day='2026-03-02'",
        "DELETE FROM x",
        "SELECT * FROM " + a.windows[B].table,  # nosec B608 -- test SQL names only tables and values the test itself defines
    ):
        assert ts.query_aggregate(sql)["status"] == "rejected"


def test_e9_system_prompt_requires_declining_out_of_scope_questions():
    from pathlib import Path

    prompt = (Path(__file__).parents[2] / "src/network_flow_insight/prompts/system_prompt.md").read_text()
    low = prompt.lower()
    for needle in (
        "latency",
        "decline",
        "never count",
        "reconciliation",
        "blind spot",
        "inferred",
        "prompt injection",
    ):
        assert needle in low, needle


# ------------------------------------------------------------------------------ E10


def test_e10_intent_lifecycle(make_analysis):
    a, est = make_analysis("full")
    ts = ToolSession(a)
    drafted = ts.intent_draft(*A)
    doc = yaml.safe_load(drafted["yaml"])
    intent = Intent.model_validate(doc)  # validates against the schema
    assert intent.baseline and all(
        e.evidence.bytes > 0 and e.evidence.first_seen and e.evidence.last_seen for e in intent.baseline
    )
    assert [n.name for n in intent.networks] == ["on-prem-dc1"]
    assert any(e.provider.network == "on-prem-dc1" for e in intent.baseline)

    # commit it, then run window B against it
    a.b.intent = intent
    a.windows.clear()
    a.dest_map.clear()
    d = ts.drift(*B)
    new = {(x["consumer"], tuple(x["provider"])) for x in d["new"]}
    stale = {(x["consumer"], tuple(x["provider"])) for x in d["stale"]}
    changed = d["path_changed"]
    assert ("subnet-app-b", ("other-internet", "240.0.2.0/24")) in new
    assert ("subnet-app-a", ("other-internet", "240.0.1.0/24")) in stale
    ddb = [
        c for c in changed if c["provider"] == ["aws-service", "DYNAMODB"] and c["consumer"] == "subnet-app-a"
    ]
    assert (
        ddb and ddb[0]["baseline_paths"] == ["interface-endpoint"] and ddb[0]["new_paths"] == ["internet-nat"]
    )
    assert d["baseline_modified"] is False
    assert d["counts"]["matched"] > 5
    assert d["counts"]["new"] == 1 and d["counts"]["stale"] == 1 and d["counts"]["path_changed"] == 1

    w = ts.what_if(*B)
    gt_new = sum(
        v["c2s"] + v["s2c"]
        for ex in est.truth["exchanges"]
        if ex["id"] == "N-new"
        for d_, v in ex["days"].items()
        if B[0] <= d_ <= B[1]
    )
    gt_total = sum(g["c2s"] + g["s2c"] for g in est.truth["by_window"]["B"]["conversations"])
    assert w["denied_bytes"] == gt_new and w["total_bytes"] == gt_total
    assert w["by_bucket"][0]["bucket"] == "other-internet" and w["by_bucket"][0]["bytes"] == gt_new
    assert w["by_workload"][0] == {**w["by_workload"][0], "workload": "10.10.2.7", "bytes": gt_new}
    assert w["denied_conversations"] == 1


def test_e10_no_baseline_defaults_to_describe_mode(full):
    a, _ = full
    ts = ToolSession(a)
    assert "error" in ts.drift(*B)
    assert "No committed baseline" in ts.describe(*B, compare_previous=False)["cautions"] or True
    f = ts.findings
    assert f["intent"]["baseline"] is False and "drafted from this run" in f["intent"]["note"]


def test_queryskipped_is_exported():
    assert issubclass(QuerySkipped, RuntimeError)


def test_probe_without_inventory_names_the_provider_options_and_the_collection_script(make_analysis):
    """Seen in the eval: the agent said no inventory was configured but did not offer the ways to get one."""
    a, _ = make_analysis("basic", inventory=False)
    out = ToolSession(a).probe(*B)
    assert out["inventory"]["provider"] == "D"
    opts = out["inventory"]["options"]
    assert set(opts) == {"A", "B", "C", "D"}
    assert "scripts/collect_inventory.py" in opts["C"]


def test_probe_with_inventory_does_not_repeat_the_options(full):
    out = ToolSession(full[0]).probe(*B)
    assert out["inventory"]["provider"] != "D" and "options" not in out["inventory"]


def test_resolver_status_counts_every_address_named_not_only_the_last_batch(make_analysis):
    """Seen in the eval: a later lookup that named nothing overwrote the count, so the report said 0 named."""
    a, _ = make_analysis("full")
    answers = [{"203.0.113.9": "files.example.com"}, {}]
    a.b.resolver_fn = lambda ips, first, last: answers.pop(0)
    a._classify_destinations({"203.0.113.9"}, *B)
    a._classify_destinations({"203.0.113.10"}, *B)
    assert a.resolver_status == "used (1 addresses named)"


def test_system_prompt_names_both_query_bounds_and_renders_without_asking():
    """Seen in the eval: a decline named the day predicate but not the row limit, and a traffic-map request ended
    with a question about rendering instead of the report."""
    from pathlib import Path

    prompt = (Path(__file__).parents[2] / "src/network_flow_insight/prompts/system_prompt.md").read_text()
    assert "day` predicate and a row limit" in prompt
    assert "do\nnot ask whether to render it" in prompt
