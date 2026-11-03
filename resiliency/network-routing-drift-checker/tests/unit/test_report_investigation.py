# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Report variants with a DevOps Agent investigation (tasks.md 3.5, requirements §10.2).

Golden text: if a change to the wording is intended, regenerate with
  UPDATE_GOLDEN=1 .venv/bin/pytest tests/unit/test_report_investigation.py
and review the diff of tests/fixtures/report_golden/ before committing.
"""

import os
import pathlib

import pytest

from drift_core import report
from drift_core.investigation import merge_investigations, normalize

GOLDEN = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "report_golden"
URI = "s3://bucket/runs/r1/findings.json"
URL1 = "https://space.aidevops.global.app.aws/investigation/t1"
URL2 = "https://space.aidevops.global.app.aws/investigation/t2"
EVALUATION = {"checks_run": ["check1", "check2", "check3", "check4", "check5", "check6"],
              "resources_evaluated": 15, "regions_not_evaluated": {}}


def fid(n):
    return f"f-{n:020x}"


def finding(n, kind, region, message):
    return {"finding_id": fid(n), "kind": kind, "severity": "drift", "region": region, "message": message}


NEW = [finding(1, "blackhole-route", "eu-central-1", "Blackhole route 10.100.0.0/16 (static) in tgw-rtb-0prd."),
       finding(2, "hybrid-path-prefix-not-found", "global", "Hybrid path 10.100.0.0/16: not installed."),
       finding(3, "redundancy-bgp-down", "eu-central-1", "Redundancy pair 'fra-a': BGP peer of dxvif-0a down."),
       finding(4, "tgw-prefix-leak", "eu-west-1", "Route table tgw-rtb-0dev has route 10.200.0.0/16 from prod.")]
KNOWN = [dict(finding(9, "blackhole-route", "us-east-1", "Blackhole route 0.0.0.0/0 in tgw-rtb-0lab."),
              first_seen="2026-10-13T05:00:00Z", age_days=2)]
DIFF = {"new": NEW, "known": KNOWN, "resolved": []}
KINDS = {f["finding_id"]: f["kind"] for f in NEW}
BATCHES = [{"batch_n": 1, "incident_id": "nrdc-r1-1", "finding_ids": [fid(1), fid(2), fid(3)]},
           {"batch_n": 2, "incident_id": "nrdc-r1-2", "finding_ids": [fid(4)]}]


def incident(rank, title, members, confidence, blast, evidence, actor, commands):
    return {"rank": rank, "title": title, "member_finding_ids": members, "root_cause_hypothesis": f"Hypothesis {rank}.",
            "confidence": confidence, "evidence": evidence, "actor_identified": actor, "blast_radius": blast,
            "stable_for": "P0D", "validation_commands": commands}


def batch1_result():
    doc = {"schema": "nrdc-investigation/v1", "incidentId": "nrdc-r1-1", "investigation_url": URL1,
           "unassigned_finding_ids": [fid(3)], "notes": "",
           "incidents": [
               # The agent ranks the dev-sized one first; code re-sorts by score.
               incident(1, "Orphaned static route blackholes 10.100.0.0/16 in prod", [fid(1), fid(2)], "high",
                        {"prefixes": 1, "attachments": 1, "domains": 1, "environment": "prod"},
                        [{"type": "cloudtrail", "event_id": "ev-1", "event_name": "DeleteTransitGatewayVpcAttachment",
                          "time": "2026-10-14T14:03:11Z", "actor": "arn:aws:sts::123456789012:assumed-role/Net/jdoe"},
                         {"type": "state", "resource": "tgw-rtb-0prd", "observation": "10.100.0.0/16 blackhole"}],
                        True, ["aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-0prd "
                               "--filters Name=state,Values=blackhole --region eu-central-1"])]}
    return normalize(doc, finding_kinds=KINDS, production_values=("prod",), default_url=URL1)


def batch2_result():
    doc = {"schema": "nrdc-investigation/v1", "incidentId": "nrdc-r1-2", "unassigned_finding_ids": [],
           "incidents": [incident(1, "Dev route table learns a prod prefix", [fid(4)], "low",
                                  {"prefixes": 1, "attachments": 1, "domains": 1, "environment": "dev"},
                                  [{"type": "health", "event_arn": "arn:aws:health:eu-west-1::event/EC2/X/Y"}],
                                  False, [])]}
    return normalize(doc, finding_kinds=KINDS, production_values=("prod",), default_url=URL2)


def merged(outcomes):
    return merge_investigations([f["finding_id"] for f in NEW], BATCHES, outcomes, KINDS)


VARIANTS = {
    "investigated": lambda: merged({1: {"status": "ok", "result": batch1_result()},
                                    2: {"status": "ok", "result": batch2_result()}}),
    "partial_failure": lambda: merged({1: {"status": "ok", "result": batch1_result()},
                                       2: {"status": "failed", "reason": "timeout-running"}}),
    "total_failure": lambda: merged({1: {"status": "failed", "reason": "NO_RESULT"},
                                     2: {"status": "failed", "reason": "timeout-never-started"}}),
}


def compose(investigation):
    return report.compose(date="2026-10-15", run_id="r1", evaluation=EVALUATION, diff=DIFF, findings_uri=URI,
                          handoff_enabled=True, investigation=investigation)


@pytest.mark.parametrize("name", sorted(VARIANTS))
def test_report_matches_golden_text(name):
    rep = compose(VARIANTS[name]())
    text = f"Subject: {rep.subject}\n\n{rep.body}\n"
    path = GOLDEN / f"{name}.txt"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8")


def test_investigated_lists_incidents_in_code_order_with_links():
    rep = compose(VARIANTS["investigated"]())
    body = rep.body
    assert rep.subject.endswith("(investigated)")
    assert body.index("1. Orphaned static route") < body.index("2. Dev route table") < body.index("\nNEW (4)\n")
    assert "blast radius score 1110 (1 prefixes, 1 attachments, 1 domains, Environment=prod)" in body
    assert f"Investigation: {URL1}" in body and f"Investigation: {URL2}" in body
    assert f"Not explained by the investigation: {fid(3)}" in body
    assert report.NO_HANDOFF not in body and report.NO_NEW not in body


def test_partial_failure_names_the_batch_and_keeps_raw_findings():
    rep = compose(VARIANTS["partial_failure"]())
    assert rep.subject.endswith("(partly investigated)")
    assert "Investigation batch 2 failed: timeout-running; its raw findings follow in NEW." in rep.body
    assert fid(4) in rep.body.split("\nNEW (4)\n")[1]


def test_total_failure_says_investigation_failed():
    rep = compose(VARIANTS["total_failure"]())
    assert rep.subject.endswith("(investigation failed)")
    assert "Investigation failed: batch 1: NO_RESULT; batch 2: timeout-never-started. Raw findings follow." in rep.body


def test_invariant_violation_is_surfaced_as_not_verified():
    inv = merge_investigations([f["finding_id"] for f in NEW] + [fid(77)], BATCHES,
                               {1: {"status": "ok", "result": batch1_result()},
                                2: {"status": "ok", "result": batch2_result()}}, KINDS)
    body = compose(inv).body
    assert "Not verified: the investigation batches did not cover the NEW findings exactly" in body
    assert fid(77) in body


def test_subject_stays_within_limit():
    rep = compose(VARIANTS["partial_failure"]())
    assert len(rep.subject) <= report.SUBJECT_MAX


@pytest.mark.parametrize("value, text", [("P0D", "0 days"), ("P1D", "1 day"), ("P2W", "14 days"),
                                         ("P1W3D", "10 days"), ("PT5H", "PT5H"), ("P", "P"), (None, "None")])
def test_stable_for_is_shown_in_days(value, text):
    assert report._duration(value) == text


def test_long_hypothesis_is_shortened_with_a_pointer():
    long_text = "word " * 200
    short = report._short(long_text, has_link=True)
    assert len(short) <= report.HYPOTHESIS_MAX + 40 and short.endswith("(full text in the investigation)")
    assert report._short("brief", has_link=True) == "brief"
    assert report._short(long_text, has_link=False).endswith(" …")
