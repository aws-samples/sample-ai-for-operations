# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Runtime role scoping and invoker retry settings, checked on a freshly synthesized stack."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASE_CTX = {"flowLogBucketName": "example-flow-logs"}


def _ec2_actions_the_code_calls() -> set[str]:
    """The EC2 describe actions provider A calls, read from the code so the role cannot drift from it."""
    src = (ROOT / "src" / "network_flow_insight" / "core" / "inventory" / "ec2.py").read_text()
    ops = set(re.findall(r'_paginate\(\s*ec2,\s*"([a-z_]+)"', src)) | set(re.findall(r"\bec2\.([a-z_]+)\(", src))
    return {"ec2:" + "".join(w.capitalize() for w in op.split("_")) for op in ops if op.startswith("describe_")}


# Reads left on Resource "*". The eight EC2 describe calls and pricing:GetProducts have no resource type in AWS's published
# IAM data. The two CloudWatch actions list a `dataset` type that AWS documents for OpenTelemetry metrics; classic metric
# reads are not shown to be authorized against it, so they stay on "*". ecr:GetAuthorizationToken is the grant CDK adds
# for the container image asset.
CLOUDWATCH_READS = {"cloudwatch:GetMetricData", "cloudwatch:ListMetrics"}
UNSCOPABLE_READS = _ec2_actions_the_code_calls() | CLOUDWATCH_READS | {"pricing:GetProducts", "ecr:GetAuthorizationToken"}


def _synth(out: Path, **ctx: str) -> subprocess.CompletedProcess:
    """Synthesize by running the CDK app directly, the way the CDK CLI launches it (the command in infra/cdk.json).

    The command is a fixed list. The output directory and the context travel in the environment, so no value from a
    test is ever part of the command line. The context from infra/cdk.json (feature flags) is merged in, as the CLI does.
    """
    if not shutil.which("npx") or not (ROOT / "infra" / "node_modules").exists():
        pytest.skip("CDK toolchain not installed; run `make synth`")
    cdk_json = json.loads((ROOT / "infra" / "cdk.json").read_text())
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}  # no credentials, as in the unit run
    env["CDK_OUTDIR"] = str(out)
    env["CDK_CONTEXT_JSON"] = json.dumps({**cdk_json.get("context", {}), **BASE_CTX, **ctx})
    return subprocess.run(  # noqa: S603
        ["npx", "ts-node", "--prefer-ts-exts", "bin/app.ts"],  # noqa: S607
        cwd=ROOT / "infra",
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


@pytest.fixture(scope="module")
def default_template(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth-default")
    done = _synth(out)
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads((out / "NetworkFlowInsight.template.json").read_text())


@pytest.fixture(scope="module")
def aggregator_template(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth-aggregator")
    done = _synth(out, configAggregatorName="example-aggregator")
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads((out / "NetworkFlowInsight.template.json").read_text())


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _statements(template: dict):
    for res in template["Resources"].values():
        if res["Type"] == "AWS::IAM::Policy":
            yield from res["Properties"]["PolicyDocument"]["Statement"]


def _with_action(template: dict, action: str) -> list[dict]:
    return [s for s in _statements(template) if action in _as_list(s["Action"])]


def test_prefix_list_read_is_scoped_by_type_and_region_not_account(default_template):
    (st,) = _with_action(default_template, "ec2:GetManagedPrefixListEntries")
    resource = json.dumps(st["Resource"])
    assert '"*"' not in resource and "prefix-list/*" in resource
    # AWS-managed lists (gateway endpoints) belong to another account, so the account segment stays open
    assert ":ec2:" in resource and ":*:prefix-list/*" in resource and "AWS::AccountId" not in resource


def test_the_remaining_wildcard_reads_are_only_those_without_a_resource_type(default_template):
    wide = [s for s in _statements(default_template) if s["Effect"] == "Allow" and "*" in _as_list(s["Resource"])]
    read_actions = {a for s in wide for a in _as_list(s["Action"]) if not a.startswith("xray:")}
    assert read_actions == UNSCOPABLE_READS


def test_no_config_permission_without_an_aggregator(default_template):
    actions = {a for s in _statements(default_template) for a in _as_list(s["Action"])}
    assert not [a for a in actions if a.startswith("config:")]
    runtime = next(r for r in default_template["Resources"].values() if r["Type"] == "AWS::BedrockAgentCore::Runtime")
    assert "NFI_CONFIG_AGGREGATOR" not in runtime["Properties"]["EnvironmentVariables"]


def test_aggregator_permission_is_scoped_to_aggregators_in_this_account(aggregator_template):
    actions = {a for s in _statements(aggregator_template) for a in _as_list(s["Action"])}
    assert "config:DescribeConfigurationAggregators" not in actions
    (st,) = _with_action(aggregator_template, "config:SelectAggregateResourceConfig")
    resource = json.dumps(st["Resource"])
    assert '"*"' not in resource and ":config:" in resource and "config-aggregator/*" in resource
    assert ":*:config-aggregator" not in resource  # the account segment is this account, never a wildcard
    runtime = next(r for r in aggregator_template["Resources"].values() if r["Type"] == "AWS::BedrockAgentCore::Runtime")
    assert runtime["Properties"]["EnvironmentVariables"]["NFI_CONFIG_AGGREGATOR"] == "example-aggregator"


@pytest.mark.parametrize("name", ["bad name", "a;b", "x" * 257])
def test_an_invalid_aggregator_name_fails_synthesis(tmp_path, name):
    done = _synth(tmp_path, configAggregatorName=name)
    assert done.returncode != 0


def test_a_failed_scheduled_run_is_never_retried(default_template):
    cfgs = [r for r in default_template["Resources"].values() if r["Type"] == "AWS::Lambda::EventInvokeConfig"]
    assert cfgs and all(c["Properties"]["MaximumRetryAttempts"] == 0 for c in cfgs)


# ------------------------------------------------------------------------------ the wildcard reads, class by class


def test_the_code_calls_the_eight_ec2_describe_actions_it_is_expected_to():
    assert _ec2_actions_the_code_calls() == {
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeManagedPrefixLists",
        "ec2:DescribeTransitGatewayAttachments",
    }


def test_the_role_grants_exactly_the_ec2_describe_actions_the_code_calls(default_template):
    granted = {a for s in _statements(default_template) for a in _as_list(s["Action"]) if a.startswith("ec2:Describe")}
    assert granted == _ec2_actions_the_code_calls()
    assert not [a for s in _statements(default_template) for a in _as_list(s["Action"]) if a.endswith("*") and ":" in a
                and a.split(":")[0] in ("ec2", "cloudwatch", "pricing", "config")]


def test_ec2_cloudwatch_and_pricing_reads_are_in_separate_statements(default_template):
    wide = [s for s in _statements(default_template) if s["Effect"] == "Allow" and "*" in _as_list(s["Resource"])]
    groups = {s.get("Sid"): set(_as_list(s["Action"])) for s in wide if s.get("Sid")}
    assert groups["ReadEc2Inventory"] == _ec2_actions_the_code_calls()
    assert groups["ReadGatewayMetrics"] == CLOUDWATCH_READS
    assert groups["ReadPrices"] == {"pricing:GetProducts"}


# ------------------------------------------------------------------------------ run budget and workgroup cutoff

DEFAULT_CUTOFF = 1_000_000_000_000  # 1 TB, decimal: the unit the cost gauge uses


@pytest.fixture(scope="module")
def limits_template(tmp_path_factory):
    out = tmp_path_factory.mktemp("synth-limits")
    done = _synth(out, maxToolCalls="25", runDeadlineSeconds="600", athenaBytesScannedCutoff="50000000000")
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads((out / "NetworkFlowInsight.template.json").read_text())


def _workgroup(template: dict) -> dict:
    return next(r for r in template["Resources"].values() if r["Type"] == "AWS::Athena::WorkGroup")["Properties"]


def _runtime_env(template: dict) -> dict:
    runtime = next(r for r in template["Resources"].values() if r["Type"] == "AWS::BedrockAgentCore::Runtime")
    return runtime["Properties"]["EnvironmentVariables"]


def test_the_workgroup_stops_a_query_that_scans_more_than_the_cutoff(default_template):
    cfg = _workgroup(default_template)["WorkGroupConfiguration"]
    assert cfg["BytesScannedCutoffPerQuery"] == DEFAULT_CUTOFF
    assert cfg["EnforceWorkGroupConfiguration"] is True


def test_the_cutoff_can_be_set_by_the_deployer(limits_template):
    assert _workgroup(limits_template)["WorkGroupConfiguration"]["BytesScannedCutoffPerQuery"] == 50_000_000_000


@pytest.mark.parametrize("value", ["5", "9999999", "1.5", "abc", "-1"])
def test_a_cutoff_below_athenas_minimum_or_not_an_integer_fails_synthesis(tmp_path, value):
    assert _synth(tmp_path, athenaBytesScannedCutoff=value).returncode != 0


def test_the_run_budget_is_left_to_the_code_defaults_unless_set(default_template):
    env = _runtime_env(default_template)
    assert "NFI_MAX_TOOL_CALLS" not in env and "NFI_RUN_DEADLINE_SECONDS" not in env


def test_the_run_budget_reaches_the_runtime_when_set(limits_template):
    env = _runtime_env(limits_template)
    assert env["NFI_MAX_TOOL_CALLS"] == "25" and env["NFI_RUN_DEADLINE_SECONDS"] == "600"


@pytest.mark.parametrize(
    "ctx",
    [
        {"maxToolCalls": "abc"},
        {"maxToolCalls": "-3"},
        {"maxToolCalls": "1.5"},
        {"runDeadlineSeconds": "abc"},
        {"runDeadlineSeconds": "801"},  # the hard stop is the deadline plus 60 s and the invoker waits 880 s
    ],
)
def test_an_invalid_run_budget_fails_synthesis(tmp_path, ctx):
    assert _synth(tmp_path, **ctx).returncode != 0


def test_a_deadline_the_invoker_can_outlast_is_accepted(tmp_path):
    out = tmp_path / "ok"
    out.mkdir()
    assert _synth(out, runDeadlineSeconds="800").returncode == 0


# ------------------------------------------------------------------------------ no cross-account role in the hosted role


@pytest.fixture(scope="module")
def removed_role_context_template(tmp_path_factory):
    """The context key that used to add an sts:AssumeRole grant. It must now grant nothing."""
    out = tmp_path_factory.mktemp("synth-removed-key")
    done = _synth(out, assumableRoleArns="arn:aws:iam::123456789012:role/example-read-only")
    assert done.returncode == 0, done.stderr[-800:]
    return json.loads((out / "NetworkFlowInsight.template.json").read_text())


def test_the_hosted_role_has_no_sts_action(default_template):
    assert not [a for s in _statements(default_template) for a in _as_list(s["Action"]) if a.startswith("sts:")]


def test_the_removed_assumable_roles_key_grants_nothing(removed_role_context_template):
    template = removed_role_context_template
    assert not [a for s in _statements(template) for a in _as_list(s["Action"]) if a.startswith("sts:")]
    assert "example-read-only" not in json.dumps(template)
