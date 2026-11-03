# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Operational test for tasks.md 1.4: CloudFormation rejects bad parameters.

Usage: .venv/bin/python tests/operational/check_parameter_rejection.py --profile <p> --region <r>
Requires a synthesized template (any `pytest tests/iam` run creates infra/cdk.out.test/).

How CloudFormation enforces each kind of check (observed 2026-10-13):
- Parameter constraints (required value, AllowedPattern) are rejected synchronously by the API.
- Template Rules are enforced when the stack operation EXECUTES: CreateStack / a change set is
  accepted, then the operation fails and rolls back with the rule's AssertDescription.

So each case deploys a throwaway stack made of the real template's Parameters and Rules plus one
free AWS::CloudFormation::WaitConditionHandle, records the outcome, and deletes the stack. The
deployed checker stack is never modified.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import boto3
from botocore.exceptions import ClientError

TEMPLATE = pathlib.Path(__file__).resolve().parents[2] / "infra" / "cdk.out.test" / \
    "NetworkRoutingDriftChecker.template.json"
URL = "https://event-ai.us-east-1.api.aws/webhook/generic/abc123"
SPACE = "8f6187a7-0388-4926-8217-3a0fe32f757c"
SECRET = "/nrdc/hmac"  # nosec B105 -- an SSM parameter name, not a secret value
TZ = {"ScheduleTimezone": "Europe/Berlin"}

# (name, parameter values, expected outcome: "created" | "api-rejected" | "rule-rollback")
CASES = [
    ("missing ScheduleTimezone", {}, "api-rejected"),
    ("invalid ScheduleTimezone", {"ScheduleTimezone": "CET; drop"}, "api-rejected"),
    ("malformed webhook URL", {**TZ, "EnableDevOpsAgentHandoff": "true", "DevOpsAgentWebhookUrl": "http://x.example.com",
                               "WebhookSecretParameterName": SECRET, "DevOpsAgentSpaceId": SPACE}, "api-rejected"),
    ("hand-off on, only URL", {**TZ, "EnableDevOpsAgentHandoff": "true", "DevOpsAgentWebhookUrl": URL},
     "rule-rollback"),
    ("hand-off on, no space ID", {**TZ, "EnableDevOpsAgentHandoff": "true", "DevOpsAgentWebhookUrl": URL,
                                  "WebhookSecretParameterName": SECRET}, "rule-rollback"),
    ("hand-off on, only secret", {**TZ, "EnableDevOpsAgentHandoff": "true", "WebhookSecretParameterName": SECRET},
     "rule-rollback"),
    ("hand-off off, space ID set", {**TZ, "DevOpsAgentSpaceId": SPACE}, "rule-rollback"),
    ("control: defaults", {**TZ}, "created"),
    ("control: hand-off fully set", {**TZ, "EnableDevOpsAgentHandoff": "true", "DevOpsAgentWebhookUrl": URL,
                                     "WebhookSecretParameterName": SECRET, "DevOpsAgentSpaceId": SPACE}, "created"),
]


def probe_template() -> str:
    real = json.loads(TEMPLATE.read_text())
    keys = ["ScheduleTimezone", "EnableDevOpsAgentHandoff", "DevOpsAgentWebhookUrl", "WebhookSecretParameterName",
            "DevOpsAgentSpaceId"]
    return json.dumps({
        "Parameters": {k: real["Parameters"][k] for k in keys},
        "Rules": {k: v for k, v in real["Rules"].items() if k.startswith("Handoff")},
        "Resources": {"Probe": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                                "Metadata": {k: {"Ref": k} for k in keys}}},
    })


def _wait(cfn, name: str) -> str:
    for _ in range(100):
        status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            return status
        time.sleep(3)
    return "TIMEOUT"


def _rollback_reason(cfn, name: str) -> str:
    for event in cfn.describe_stack_events(StackName=name)["StackEvents"]:
        text = event.get("ResourceStatusReason") or ""
        if "EnableDevOpsAgentHandoff" in text or "Assertion" in text or "Rule" in text:
            return text
    return ""


def _delete(cfn, name: str) -> None:
    try:
        cfn.delete_stack(StackName=name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=name, WaiterConfig={"Delay": 3, "MaxAttempts": 60})
    except ClientError:
        pass


def run_case(cfn, template: str, index: int, values: dict[str, str]) -> tuple[str, str]:
    name = f"nrdc-param-probe-{int(time.time())}-{index}"
    params = [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]
    try:
        cfn.create_stack(StackName=name, TemplateBody=template, Parameters=params)
    except ClientError as exc:
        return "api-rejected", exc.response["Error"]["Message"][:160]
    try:
        status = _wait(cfn, name)
        if status == "CREATE_COMPLETE":
            return "created", status
        reason = _rollback_reason(cfn, name)
        return ("rule-rollback" if reason else f"failed:{status}"), reason[:160] or status
    finally:
        _delete(cfn, name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--region", required=True)
    args = ap.parse_args()
    cfn = boto3.Session(profile_name=args.profile, region_name=args.region).client("cloudformation")
    template = probe_template()
    failures = 0
    for i, (case, values, expected) in enumerate(CASES):
        outcome, detail = run_case(cfn, template, i, values)
        ok = outcome == expected
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} | {case} | expected {expected}, got {outcome} | {detail}")
    leftovers = [s["StackName"] for s in cfn.list_stacks(StackStatusFilter=[
        "CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS"])["StackSummaries"]
        if s["StackName"].startswith("nrdc-param-probe-")]
    print("probe stacks left:", leftovers or "none")
    print("RESULT:", "all cases behaved as expected" if failures == 0 else f"{failures} case(s) wrong")
    return 1 if failures or leftovers else 0


if __name__ == "__main__":
    sys.exit(main())
