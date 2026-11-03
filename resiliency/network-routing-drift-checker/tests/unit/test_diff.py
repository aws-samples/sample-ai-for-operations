# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""NEW / KNOWN / RESOLVED (tasks.md 1.23, requirements §8, §14.1)."""

from drift_core.diff import age_days, compute, source_of
from drift_core.finding import Finding


def f(prefix="10.9.0.0/16", region="eu-central-1", severity="drift", observed=None, context=None):
    return Finding(check="check3" if severity == "drift" else "system", kind="blackhole-route", severity=severity,
                   region=region, identity=("tgw-rtb-0001", prefix), observed=observed or {"state": "blackhole"},
                   context=context or {}, message=f"Blackhole {prefix}").to_dict()


def apply(state, result):
    for w in result.writes:
        state[w["finding_id"]] = w
    return [i for i in state.values() if i["status"] == "open"]


D1, D2, D3 = "2026-05-10T05:00:00Z", "2026-05-11T05:00:00Z", "2026-05-12T05:00:00Z"
ALL = {"eu-central-1", "global", "cloudwan"}


def test_new_known_resolved_across_three_runs():
    state = {}
    r1 = compute([f()], [], ALL, D1, "r1")
    assert [len(r1.new), len(r1.known), len(r1.resolved)] == [1, 0, 0]
    r2 = compute([f()], apply(state, r1), ALL, D2, "r2")
    assert [len(r2.new), len(r2.known), len(r2.resolved)] == [0, 1, 0]
    assert r2.known[0]["first_seen"] == D1 and r2.known[0]["age_days"] == 1 and r2.known[0]["changed"] is False
    r3 = compute([], apply(state, r2), ALL, D3, "r3")
    assert [len(r3.new), len(r3.known), len(r3.resolved)] == [0, 0, 1]
    assert r3.resolved[0]["age_days"] == 2
    assert apply(state, r3) == [] and state[r1.new[0]["finding_id"]]["status"] == "resolved"
    assert "ttl" in state[r1.new[0]["finding_id"]]


def test_not_evaluated_region_keeps_finding_known_unverified():
    state = {}
    r1 = compute([f()], [], ALL, D1, "r1")
    r2 = compute([], apply(state, r1), {"global"}, D2, "r2")
    assert r2.resolved == [] and len(r2.known) == 1
    assert r2.known[0]["unverified"] is True
    assert all(w.get("status") != "resolved" for w in r2.writes)


def test_changed_payload_is_known_and_flagged():
    state = {}
    r1 = compute([f(observed={"type": "static"})], [], ALL, D1, "r1")
    r2 = compute([f(observed={"type": "propagated"})], apply(state, r1), ALL, D2, "r2")
    assert len(r2.known) == 1 and r2.known[0]["changed"] is True


def test_dedup_survives_field_order():
    state = {}
    a = f()
    b = dict(reversed(list(f().items())))
    r1 = compute([a], [], ALL, D1, "r1")
    r2 = compute([b], apply(state, r1), ALL, D2, "r2")
    assert r2.new == [] and len(r2.known) == 1


def test_resolved_finding_that_reappears_is_new_again():
    state = {}
    r1 = compute([f()], [], ALL, D1, "r1")
    r2 = compute([], apply(state, r1), ALL, D2, "r2")
    r3 = compute([f()], apply(state, r2), ALL, D3, "r3")
    assert len(r3.new) == 1 and r3.new[0]["first_seen"] == D3


def test_counts_by_severity_and_sort_order():
    findings = [f(prefix="10.2.0.0/16", severity="system"), f(prefix="10.1.0.0/16")]
    r = compute(findings, [], ALL, D1, "r1")
    assert r.counts("drift") == {"new": 1, "known": 0, "resolved": 0}
    assert [e["severity"] for e in r.new] == ["drift", "system"]
    assert r.to_dict()["drift_counts"]["new"] == 1


def test_source_and_age():
    assert source_of({"region": "eu-central-1", "context": {"core_network_id": "cn"}}) == "cloudwan"
    assert source_of({"region": "eu-west-1", "context": {}}) == "eu-west-1"
    assert source_of({"context": {}}) == "global"
    assert age_days("2026-05-10T23:59:00Z", "2026-05-11T00:01:00Z") == 1
    assert age_days(D2, D1) == 0
