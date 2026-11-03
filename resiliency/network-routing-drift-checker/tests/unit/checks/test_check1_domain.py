# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Check 1 — wrong routing domain (tasks.md 1.17, 1.18)."""

import copy

from drift_core.checks import EvaluationContext
from drift_core.checks.check1_domain import check_cloudwan, check_tgw, run
from tests.fixtures import snapshots as fx


def kinds(findings):
    return sorted(f.kind for f in findings)


# ── Cloud WAN ────────────────────────────────────────────────────────────────

def test_cloudwan_no_drift():
    assert check_cloudwan(EvaluationContext(cloudwan=fx.clean_cloudwan(), regions={})) == []


def test_cloudwan_wrong_segment_by_tag():
    cw = fx.clean_cloudwan()
    cw["attachments"][0]["segment_name"] = "dev"  # tagged prod, sits in dev
    out = check_cloudwan(EvaluationContext(cloudwan=cw, regions={}))
    assert kinds(out) == ["cloudwan-wrong-segment"]
    assert out[0].expected == {"segment": "prod"} and out[0].observed == {"segment": "dev"}
    assert out[0].identity == ("attachment-0prd",)


def test_cloudwan_wrong_segment_by_constant_rule():
    cw = fx.clean_cloudwan()
    cw["attachments"][3]["segment_name"] = "prod"  # DX gateway attachment must be in hybrid
    assert kinds(check_cloudwan(EvaluationContext(cloudwan=cw, regions={}))) == ["cloudwan-wrong-segment"]


def test_cloudwan_pending_change_is_informational():
    cw = fx.clean_cloudwan()
    cw["attachments"][0].update(segment_name="dev", proposed_segment_change=True)
    out = check_cloudwan(EvaluationContext(cloudwan=cw, regions={}))
    assert kinds(out) == ["cloudwan-segment-change-pending"] and out[0].severity == "informational"


def test_cloudwan_no_matching_rule():
    cw = fx.cloudwan([fx.cw_attachment("attachment-0unt", "dev", env=None)])
    out = check_cloudwan(EvaluationContext(cloudwan=cw, regions={}))
    assert kinds(out) == ["cloudwan-no-matching-rule"]


def test_cloudwan_non_available_skipped_and_none_snapshot():
    cw = fx.cloudwan([fx.cw_attachment("attachment-0pnd", "dev", "prod", state="PENDING_ATTACHMENT_ACCEPTANCE")])
    assert check_cloudwan(EvaluationContext(cloudwan=cw, regions={})) == []
    assert check_cloudwan(EvaluationContext(cloudwan=None, regions={})) == []


def test_cloudwan_operators_and_logic():
    policy = copy.deepcopy(fx.POLICY)
    policy["attachment-policies"] = [
        {"rule-number": 10, "condition-logic": "and", "conditions": [
            {"type": "tag-value", "operator": "begins-with", "key": "Team", "value": "net"},
            {"type": "region", "operator": "equals", "value": "eu-central-1"}],
         "action": {"association-method": "constant", "segment": "shared"}},
        {"rule-number": 20, "conditions": [{"type": "resource-id", "operator": "contains", "value": "0d"}],
         "action": {"association-method": "constant", "segment": "dev"}},
        {"rule-number": 30, "conditions": [{"type": "account-id", "operator": "not-equals", "value": "999"}],
         "action": {"association-method": "constant", "segment": "prod"}},
    ]
    atts = [fx.cw_attachment("attachment-0aaa", "shared", tags={"Team": "network"}),
            fx.cw_attachment("attachment-00d1", "dev", resource_id="vpc-0d1"),
            fx.cw_attachment("attachment-0zzz", "prod", resource_id="vpc-0zzz")]
    assert check_cloudwan(EvaluationContext(cloudwan=fx.cloudwan(atts, policy=policy), regions={})) == []


def test_cloudwan_unsupported_construct_is_system_not_drift():
    policy = copy.deepcopy(fx.POLICY)
    policy["attachment-policies"] = [{"rule-number": 1, "conditions": [{"type": "future-condition"}],
                                      "action": {"association-method": "constant", "segment": "prod"}}]
    out = check_cloudwan(EvaluationContext(cloudwan=fx.cloudwan([fx.cw_attachment("attachment-0a", "dev")],
                                                               policy=policy), regions={}))
    assert kinds(out) == ["cloudwan-rule-not-evaluated"] and out[0].severity == "system"


def test_cloudwan_network_function_group_out_of_scope():
    policy = copy.deepcopy(fx.POLICY)
    policy["attachment-policies"] = [{"rule-number": 1, "conditions": [{"type": "any"}],
                                      "action": {"add-to-network-function-group": "inspection"}}]
    cw = fx.cloudwan([fx.cw_attachment("attachment-0a", None)], policy=policy)
    assert check_cloudwan(EvaluationContext(cloudwan=cw, regions={})) == []


# ── TGW ──────────────────────────────────────────────────────────────────────

def test_tgw_no_drift_case_insensitive_trim():
    assert check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": fx.clean_region()})) == []


def test_tgw_wrong_route_table():
    r = fx.clean_region()
    r["attachments"][0]["association"]["route_table_id"] = "tgw-rtb-0dev"
    out = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))
    assert kinds(out) == ["tgw-wrong-route-table"]
    assert out[0].identity == ("tgw-attach-0prd",) and out[0].region == "eu-central-1"


def test_tgw_untagged_attachment_informational():
    r = fx.clean_region()
    r["attachments"][0]["tags"] = {}
    out = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))
    assert kinds(out) == ["untagged-attachment"] and out[0].severity == "informational"


def test_tgw_untagged_route_table_one_finding_per_table():
    r = fx.clean_region()
    r["route_tables"][0]["tags"] = {}
    r["attachments"].append(fx.tgw_attachment("tgw-attach-0pr2", "dev", "tgw-rtb-0prd"))
    out = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))
    assert kinds(out) == ["untagged-route-table"]
    assert out[0].observed["attachments"] == ["tgw-attach-0pr2", "tgw-attach-0prd"]


def test_untagged_route_table_id_stable_payload_changes_with_attachments():
    """Adding an attachment keeps the same KNOWN finding but flips payload_hash (requirements §6)."""
    r = fx.clean_region()
    r["route_tables"][0]["tags"] = {}
    before = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))[0]
    r["attachments"].append(fx.tgw_attachment("tgw-attach-0pr3", "prod", "tgw-rtb-0prd"))
    after = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))[0]
    assert before.finding_id == after.finding_id
    assert before.identity == after.identity == ("tgw-rtb-0prd",)
    assert before.payload_hash != after.payload_hash


def test_untagged_attachment_keyed_per_attachment():
    r = fx.clean_region()
    r["attachments"][0]["tags"] = {}
    r["attachments"][1]["tags"] = {}
    out = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}))
    assert sorted(f.identity for f in out) == [("tgw-attach-0dev",), ("tgw-attach-0prd",)]


def test_tgw_custom_tag_key_and_unassociated_skipped():
    r = fx.clean_region()
    for obj in r["route_tables"] + r["attachments"]:
        obj["tags"] = {"Stage": obj["tags"].get("Environment", "")}
    r["attachments"].append(fx.tgw_attachment("tgw-attach-0new", "prod", None))
    r["attachments"].append(fx.tgw_attachment("tgw-attach-0del", "dev", "tgw-rtb-0prd", state="deleting"))
    out = check_tgw(EvaluationContext(cloudwan=None, regions={"eu-central-1": r}, environment_tag_key="stage"))
    assert out == []


def test_tgw_multiple_regions_and_tgws_independent():
    a = fx.clean_region("eu-central-1")
    b = fx.clean_region("eu-west-1")
    b["attachments"][1]["association"]["route_table_id"] = "tgw-rtb-0prd"
    out = run(EvaluationContext(cloudwan=None, regions={"eu-central-1": a, "eu-west-1": b}))
    assert [(f.kind, f.region) for f in out] == [("tgw-wrong-route-table", "eu-west-1")]
