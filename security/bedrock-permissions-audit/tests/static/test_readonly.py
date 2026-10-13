# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Requirement E16: the tool and everything it ships are read-only. This is a build gate.

Four independent checks:
  1. Every AWS API call in src/ is a read (AST scan against botocore's own service models).
  2. src/ cannot call an API indirectly (no getattr, eval, exec on clients).
  3. Every action in the shipped IAM documents is on a read-only allowlist.
  4. The shipped policies grant at least what the code calls, so they are not under-privileged.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import botocore.session
import pytest
import yaml
from botocore import xform_name

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "bedrock_permissions_audit"
SERVICES = ("iam", "sts", "organizations")

# The complete set of AWS operations the tool may call. generate_credential_report is the only
# one that is not a pure read: it asks IAM to refresh a report that IAM itself keeps for 4 hours.
ALLOWED_OPERATIONS = {
    "iam": {
        "generate_credential_report",
        "get_credential_report",
        "list_users",
        "list_access_keys",
        "get_access_key_last_used",
        "list_service_specific_credentials",
        "list_attached_user_policies",
        "list_groups_for_user",
        "list_attached_group_policies",
        "list_mfa_devices",
        # Read to find the Amazon Bedrock resources a user's own policies name. The documents are
        # held in memory only; see collectors/policy_resources.py.
        "list_user_policies",
        "get_user_policy",
        "list_group_policies",
        "get_group_policy",
        "get_policy",
        "get_policy_version",
        "simulate_principal_policy",
    },
    "sts": {"get_caller_identity", "assume_role"},
    "organizations": {"list_accounts"},
}
READ_PREFIXES = ("get_", "list_", "describe_")
EXTRA_NON_READ = {"generate_credential_report", "simulate_principal_policy", "assume_role"}

# IAM actions the shipped policies may grant: the operations above, plus the reads the policy
# simulator performs on the caller's behalf, plus organizations discovery.
SIMULATOR_SUPPORT = {
    "iam:GetUser",
    "iam:GetUserPolicy",
    "iam:ListUserPolicies",
    "iam:GetGroupPolicy",
    "iam:ListGroupPolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetAccountSummary",
}
EXTRA_ALLOWED_ACTIONS = SIMULATOR_SUPPORT | {"organizations:DescribeOrganization"}


def operation_maps():
    """snake_case name -> IAM action (service:CamelCase) for each service the tool uses."""
    session = botocore.session.get_session()
    maps: dict[str, dict[str, str]] = {}
    for service in SERVICES:
        model = session.get_service_model(service)
        maps[service] = {xform_name(op): f"{service}:{op}" for op in model.operation_names}
    return maps


OPERATIONS = operation_maps()
ALL_SNAKE_TO_ACTION = {
    snake: action for ops in OPERATIONS.values() for snake, action in ops.items()
}
ALLOWED_ACTIONS_FROM_CODE = {
    OPERATIONS[service][name] for service, names in ALLOWED_OPERATIONS.items() for name in names
}
ALLOWED_ACTIONS = ALLOWED_ACTIONS_FROM_CODE | EXTRA_ALLOWED_ACTIONS


def python_files(directory: Path):
    return sorted(p for p in directory.rglob("*.py") if "__pycache__" not in p.parts)


def parse(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def called_operations(tree: ast.AST) -> set[str]:
    """snake_case operation names called as methods, or opened as paginators, in a module."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Attribute) and function.attr in ALL_SNAKE_TO_ACTION:
            found.add(function.attr)
        if (
            isinstance(function, ast.Attribute)
            and function.attr == "get_paginator"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            found.add(str(node.args[0].value))
    return found


def is_read_only(operation: str) -> bool:
    return operation.startswith(READ_PREFIXES) or operation in EXTRA_NON_READ


def source_operations() -> dict[str, set[str]]:
    return {str(p.relative_to(ROOT)): called_operations(parse(p)) for p in python_files(SRC)}


# ---------------------------------------------------------------------------------------------
# 1. Calls
# ---------------------------------------------------------------------------------------------


def test_installed_boto3_supports_account_wide_api_key_listing():
    """The declared boto3 floor must really have the AllUsers parameter, and so must the one
    installed here; this failed silently once when another tool pinned an older boto3."""
    import boto3

    members = (
        boto3.client("iam", region_name="us-east-1")
        .meta.service_model.operation_model("ListServiceSpecificCredentials")
        .input_shape.members
    )
    assert "AllUsers" in members
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"boto3>=1.39"' in pyproject


def test_the_scan_actually_finds_calls():
    """Guard against the scan silently matching nothing."""
    used = set().union(*source_operations().values())
    assert {"list_users", "simulate_principal_policy", "assume_role", "list_accounts"} <= used


def test_every_operation_called_in_src_is_on_the_allowlist():
    allowed = set().union(*ALLOWED_OPERATIONS.values())
    offenders = {
        path: sorted(ops - allowed) for path, ops in source_operations().items() if ops - allowed
    }
    assert not offenders, f"operations outside the allowlist: {offenders}"


def test_every_operation_called_in_src_is_a_read_or_a_known_exception():
    offenders = {
        path: sorted(op for op in ops if not is_read_only(op))
        for path, ops in source_operations().items()
        if any(not is_read_only(op) for op in ops)
    }
    assert not offenders, f"non-read operations: {offenders}"


def test_allowlist_itself_contains_only_reads_and_the_documented_exceptions():
    every = set().union(*ALLOWED_OPERATIONS.values())
    assert {op for op in every if not is_read_only(op)} == set()
    assert EXTRA_NON_READ >= {
        "generate_credential_report",
        "simulate_principal_policy",
        "assume_role",
    }


def test_only_the_expected_services_get_clients():
    services = set()
    for path in python_files(SRC):
        for node in ast.walk(parse(path)):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "client"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                services.add(node.args[0].value)
    assert services <= set(SERVICES), services


def test_the_scan_would_catch_a_mutating_call():
    """Prove the detector works by feeding it code that deletes a key."""
    tree = ast.parse("iam.delete_access_key(UserName='a', AccessKeyId='b')")
    assert called_operations(tree) == {"delete_access_key"}
    assert not is_read_only("delete_access_key")
    paginator = ast.parse("iam.get_paginator('delete_user')")
    assert called_operations(paginator) == {"delete_user"}


# ---------------------------------------------------------------------------------------------
# 2. No indirection
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", ["getattr", "eval", "exec", "__import__", "compile"])
def test_src_has_no_dynamic_dispatch(forbidden):
    """A getattr(client, name)(...) would let any API be called without the scan seeing it."""
    offenders = [
        f"{p.relative_to(ROOT)}:{node.lineno}"
        for p in python_files(SRC)
        for node in ast.walk(parse(p))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == forbidden
    ]
    assert not offenders, offenders


def test_src_does_not_shell_out():
    offenders = [
        str(p.relative_to(ROOT))
        for p in python_files(SRC)
        for node in ast.walk(parse(p))
        if isinstance(node, ast.Import | ast.ImportFrom)
        and any(
            name in {"subprocess", "os.system"}
            for name in (
                [a.name for a in node.names]
                + ([node.module] if isinstance(node, ast.ImportFrom) else [])
            )
        )
    ]
    assert not offenders, offenders


def test_src_does_not_use_the_network_except_through_the_aws_sdk():
    banned = {"requests", "urllib", "http", "socket", "httpx", "aiohttp", "ftplib", "smtplib"}
    offenders = []
    for path in python_files(SRC):
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            else:
                continue
            if banned & set(names):
                offenders.append(f"{path.relative_to(ROOT)}: {sorted(banned & set(names))}")
    assert not offenders, offenders


def test_no_llm_or_ai_sdk_is_imported_or_declared():
    """The tool is deterministic. Nothing may import an AI SDK or declare one as a dependency.
    (Calling Amazon Bedrock itself is ruled out by test_only_the_expected_services_get_clients.)"""
    banned = {"strands", "anthropic", "openai", "langchain", "llama_index", "litellm", "mcp"}
    imported = set()
    for path in python_files(SRC):
        for node in ast.walk(parse(path)):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
    assert not banned & imported, banned & imported

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    runtime = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "boto3" in runtime
    assert not any(word in runtime for word in banned)


# ---------------------------------------------------------------------------------------------
# 3. Shipped IAM documents
# ---------------------------------------------------------------------------------------------


class CloudFormationLoader(yaml.SafeLoader):
    """Reads CloudFormation YAML, treating intrinsic function tags (!Ref, !Sub, ...) as data."""


def _intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node, deep=True)}
    return {tag_suffix: loader.construct_mapping(node, deep=True)}


CloudFormationLoader.add_multi_constructor("!", _intrinsic)


def load_template() -> dict:
    text = (ROOT / "infra" / "audit-role.yaml").read_text()
    loader = CloudFormationLoader
    return yaml.load(text, Loader=loader)  # noqa: S506  # nosec B506 -- SafeLoader subclass


def actions_in(statements) -> list[tuple[str, str]]:
    """(effect, action) pairs from a statement list; Action may be a string or a list."""
    pairs = []
    for statement in statements:
        actions = statement.get("Action", [])
        for action in [actions] if isinstance(actions, str) else actions:
            pairs.append((statement["Effect"], action))
        assert "NotAction" not in statement, "NotAction would grant everything else"
    return pairs


def shipped_permission_statements() -> dict[str, list[dict]]:
    caller = json.loads((ROOT / "infra" / "caller-policy.json").read_text())
    template = load_template()
    role = template["Resources"]["AuditRole"]["Properties"]
    return {
        "infra/caller-policy.json": caller["Statement"],
        **{
            f"infra/audit-role.yaml:{policy['PolicyName']}": policy["PolicyDocument"]["Statement"]
            for policy in role["Policies"]
        },
    }


def test_every_shipped_permission_is_on_the_read_only_allowlist():
    allowed = ALLOWED_ACTIONS | {"sts:AssumeRole", "sts:GetCallerIdentity"}
    for name, statements in shipped_permission_statements().items():
        for effect, action in actions_in(statements):
            assert effect == "Allow", (name, action)
            assert "*" not in action, f"{name}: wildcard action {action}"
            assert action in allowed, f"{name}: {action} is not on the read-only allowlist"


def test_no_shipped_permission_can_write_even_by_its_name():
    verbs = ("Create", "Delete", "Put", "Update", "Attach", "Detach", "Add", "Remove", "Set", "Tag")
    for name, statements in shipped_permission_statements().items():
        for _, action in actions_in(statements):
            verb = action.split(":", 1)[1]
            assert not verb.startswith(verbs), f"{name}: {action} looks like a write"


def test_only_the_caller_policy_may_assume_roles():
    for name, statements in shipped_permission_statements().items():
        pairs = actions_in(statements)
        has_assume = any(action == "sts:AssumeRole" for _, action in pairs)
        assert has_assume == (name == "infra/caller-policy.json"), name


def test_assume_role_in_the_caller_policy_is_scoped_to_named_roles():
    statements = shipped_permission_statements()["infra/caller-policy.json"]
    (statement,) = [s for s in statements if s["Action"] == "sts:AssumeRole"]
    resources = statement["Resource"]
    assert resources != "*"
    assert all(r.startswith("arn:aws:iam::*:role/") and not r.endswith("/*") for r in resources)


def test_the_default_role_is_the_dedicated_one_and_the_caller_policy_names_no_admin_role():
    """E27: the credential the tool holds must be the read-only role, not an administrator."""
    from bedrock_permissions_audit.config import Config

    default = Config().role_name
    assert default == load_template()["Parameters"]["RoleName"]["Default"], (
        "the default must be the role infra/audit-role.yaml creates"
    )
    statements = shipped_permission_statements()["infra/caller-policy.json"]
    (statement,) = [s for s in statements if s["Action"] == "sts:AssumeRole"]
    assert statement["Resource"] == [f"arn:aws:iam::*:role/{default}"]
    for administrator in ("OrganizationAccountAccessRole", "AWSControlTowerExecution"):
        assert administrator not in json.dumps(statement)


def test_audit_role_trust_is_limited_to_assume_role():
    trust = load_template()["Resources"]["AuditRole"]["Properties"]["AssumeRolePolicyDocument"]
    assert [s["Action"] for s in trust["Statement"]] == ["sts:AssumeRole"]
    assert all(s["Effect"] == "Allow" for s in trust["Statement"])


def test_audit_role_trusts_one_named_principal_and_never_an_account_root():
    """E26: an empty or root principal would let any identity in the account assume the role."""
    template = load_template()
    parameter = template["Parameters"]["TrustedPrincipalArn"]

    assert "Default" not in parameter, "the principal must be required"
    pattern = re.compile(parameter["AllowedPattern"])
    assert pattern.fullmatch("arn:aws:iam::123456789012:role/SecurityAuditor")
    assert pattern.fullmatch("arn:aws:iam::123456789012:role/path/to/Auditor")
    assert pattern.fullmatch("arn:aws:iam::123456789012:user/auditor")
    for rejected in ("", "123456789012", "arn:aws:iam::123456789012:root", "arn:aws:iam::1:role/x"):
        assert not pattern.fullmatch(rejected), rejected

    assert "ManagementAccountId" not in template["Parameters"]
    assert "TrustWholeAccount" not in template.get("Conditions", {})
    trust = template["Resources"]["AuditRole"]["Properties"]["AssumeRolePolicyDocument"]
    for statement in trust["Statement"]:
        assert statement["Principal"] == {"AWS": {"Ref": "TrustedPrincipalArn"}}


def test_shipped_documents_contain_no_account_ids_or_secrets():
    for path in (ROOT / "infra").iterdir():
        text = path.read_text()
        assert "AKIA" not in text and "ASIA" not in text, path
    template = (ROOT / "infra" / "audit-role.yaml").read_text()
    assert "123456789012" not in template  # no real or example account baked in


# ---------------------------------------------------------------------------------------------
# 4. Policies grant what the code needs
# ---------------------------------------------------------------------------------------------


def test_shipped_policies_cover_every_operation_the_code_calls():
    needed = {
        ALL_SNAKE_TO_ACTION[operation]
        for operations in source_operations().values()
        for operation in operations
        if operation != "assume_role"  # granted by the caller policy and the role's trust
    }
    for name, statements in shipped_permission_statements().items():
        granted = {action for _, action in actions_in(statements)}
        if name == "infra/caller-policy.json":
            assert needed <= granted, f"{name} is missing {sorted(needed - granted)}"
        else:
            member_needed = {a for a in needed if a.startswith("iam:")}
            assert member_needed <= granted, f"{name} is missing {sorted(member_needed - granted)}"
