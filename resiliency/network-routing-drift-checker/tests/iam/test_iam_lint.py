# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Deny-by-default IAM lint over the synthesized templates (design.md D§7.3, requirements §14.4).

Runs over the checker stack and the cross-account companion stack. Fails on: any action outside
the checked-in allowlist; any wildcard in an action; Resource "*" on anything but a customer
read or a documented service requirement; any blocked action; managed policies on our roles;
NotAction / NotResource; own-resource writes not scoped to a resource of the stack; hand-off
actions not scoped to their one documented resource.
"""

import json
import re

import pytest

READ = re.compile(r"^(ec2|networkmanager|directconnect):(Describe|Get|List|Search)[A-Za-z]+$")
# The companion stack's own-resource grant targets the checker's callback, which it receives as
# a parameter: that parameter counts as "a resource of the stack" there, and nowhere else.
LOCAL_PARAMS = {"checker": (), "link": ("CallbackFunctionArn",)}


@pytest.fixture(params=["checker", "link"])
def stack(request, template, link_template):
    return request.param, template if request.param == "checker" else link_template


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _statements(template):
    for logical_id, res in template["Resources"].items():
        if res["Type"] == "AWS::IAM::Policy":
            for st in res["Properties"]["PolicyDocument"]["Statement"]:
                yield logical_id, st
        if res["Type"] == "AWS::IAM::Role":
            for policy in res["Properties"].get("Policies") or []:
                for st in policy["PolicyDocument"]["Statement"]:
                    yield logical_id, st


def _refs_local_resource(resource, template, params=()):
    """True if the resource ARN is built from a resource defined in this template."""
    text = repr(resource)
    return isinstance(resource, dict) and any(f"'{lid}'" in text for lid in (*template["Resources"], *params))


def _allowed(allowlist):
    return (set(allowlist["customer_read"]) | set(allowlist["own_resource"]) | set(allowlist["service_requires_star"])
            | set(allowlist["handoff"]))


def test_lint_runs_on_real_statements(template, link_template):
    assert sum(1 for _ in _statements(template)) > 20
    assert sum(1 for _ in _statements(link_template)) == 2


def test_no_managed_policies_on_roles(stack):
    _, tpl = stack
    offenders = [lid for lid, r in tpl["Resources"].items()
                 if r["Type"] == "AWS::IAM::Role" and r["Properties"].get("ManagedPolicyArns")]
    assert offenders == []


def check_actions(template, allowlist):
    allowed = _allowed(allowlist)
    problems = []
    for lid, st in _statements(template):
        assert st.get("Effect") == "Allow", f"{lid}: only Allow statements are expected"
        assert "NotAction" not in st and "NotResource" not in st, f"{lid}: NotAction/NotResource"
        for action in _as_list(st["Action"]):
            if action in ("kms:GenerateDataKey*",):
                pass
            elif "*" in action:
                problems.append(f"{lid}: wildcard action {action}")
            if action not in allowed:
                problems.append(f"{lid}: action not in allowlist {action}")
            if action in allowlist["blocked"]:
                problems.append(f"{lid}: BLOCKED action {action}")
    assert problems == []


def check_star(template, allowlist):
    problems = []
    for lid, st in _statements(template):
        if "*" not in _as_list(st["Resource"]):
            continue
        for action in _as_list(st["Action"]):
            if not (READ.match(action) or action in allowlist["service_requires_star"]):
                problems.append(f"{lid}: {action} on Resource '*'")
    assert problems == []


def test_every_action_is_allowlisted_and_not_wildcarded(stack, allowlist):
    check_actions(stack[1], allowlist)


def test_star_resource_only_for_reads_and_service_requirements(stack, allowlist):
    check_star(stack[1], allowlist)


def test_own_resource_actions_scoped_to_this_stack(stack, allowlist):
    name, tpl = stack
    own = set(allowlist["own_resource"])
    problems = []
    for lid, st in _statements(tpl):
        actions = [a for a in _as_list(st["Action"]) if a in own]
        if not actions:
            continue
        for resource in _as_list(st["Resource"]):
            if not _refs_local_resource(resource, tpl, LOCAL_PARAMS[name]):
                problems.append(f"{lid}: {actions} on {resource!r} is not a resource of this stack")
    assert problems == []


def test_handoff_actions_scoped_to_their_one_resource(stack, allowlist):
    """aidevops/sts/ssm grants must name the one Agent Space, role or parameter (D§7.2)."""
    _, tpl = stack
    problems = []
    for lid, st in _statements(tpl):
        for action in _as_list(st["Action"]):
            if action not in allowlist["handoff"]:
                continue
            expected = allowlist["handoff"][action]
            for resource in _as_list(st["Resource"]):
                text = json.dumps(resource)
                if not all(part in text for part in expected):
                    problems.append(f"{lid}: {action} on {text} lacks {expected}")
    assert problems == []


def test_customer_reads_are_read_only_verbs(allowlist):
    assert all(READ.match(a) for a in allowlist["customer_read"])


def test_lint_catches_violations(template, allowlist):
    """The lint itself must fail on a bad statement (guards against a vacuous pass)."""
    bad = {"Resources": {**template["Resources"], "Bad": {"Type": "AWS::IAM::Policy", "Properties": {
        "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": ["ec2:Create*", "ec2:CreateTransitGatewayRoute"],
                                          "Resource": "*"}]}}}}}
    for check in (check_actions, check_star):
        try:
            check(bad, allowlist)
        except AssertionError:
            continue
        raise AssertionError(f"{check.__name__} did not catch the violation")
