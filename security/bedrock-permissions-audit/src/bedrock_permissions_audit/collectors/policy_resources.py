# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Which Amazon Bedrock resources a user's own policies name.

The policy simulator matches resource ARNs as strings, so a fixed sample of models cannot find a
policy that allows a model outside the sample. Reading the Resource entries of the user's own Allow
statements lets the evaluator test exactly what the policies name.

Policy documents are read in memory to extract resource names. They are never stored, logged or
written to any output."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from botocore.exceptions import ClientError

from ..models import Principal

logger = logging.getLogger(__name__)

# Replaces each '*' in a policy's resource pattern, so the probe ARN matches its own pattern.
WILDCARD_TOKEN = "audit-probe"  # noqa: S105  # nosec B105 -- a placeholder in an ARN


def iam_matches(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """IAM wildcard matching: '*' is any run of characters and '?' is any one character."""
    expression = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )
    flags = re.IGNORECASE if ignore_case else 0
    return re.fullmatch(expression, value, flags) is not None


def _has_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else [str(item) for item in value]


def _as_document(raw: Any) -> Mapping[str, Any]:
    """boto3 already returns policy documents decoded to a dict; accept a JSON string as well."""
    if isinstance(raw, str):
        return json.loads(raw)
    return raw


def _covers_invoke(statement: Mapping[str, Any], invoke_actions: Iterable[str]) -> bool:
    if "NotAction" in statement:
        return True  # may cover them; probing a few extra resources is cheap
    patterns = _as_list(statement.get("Action"))
    return any(
        iam_matches(pattern, action, ignore_case=True)
        for pattern in patterns
        for action in invoke_actions
    )


def is_bedrock_arn(resource: str) -> bool:
    parts = resource.split(":", 5)
    return len(parts) == 6 and parts[0] == "arn" and parts[2].startswith("bedrock")


def extract_bedrock_resources(
    document: Mapping[str, Any], invoke_actions: Sequence[str]
) -> list[str]:
    """Amazon Bedrock Resource ARNs (patterns included) of Allow statements covering an invoke.

    Deny statements are ignored, and so is NotResource: neither names a resource that is allowed."""
    statements = document.get("Statement", [])
    if isinstance(statements, Mapping):
        statements = [statements]
    found: dict[str, None] = {}
    for statement in statements:
        if statement.get("Effect") != "Allow" or "NotResource" in statement:
            continue
        if not _covers_invoke(statement, invoke_actions):
            continue
        for resource in _as_list(statement.get("Resource")):
            if is_bedrock_arn(resource):
                found.setdefault(resource, None)
    return list(found)


def probe_arns(pattern: str, regions: Sequence[str], account_id: str) -> list[str]:
    """Concrete ARNs that match a policy's resource pattern, for the simulator to test.

    Each '*' in the resource part becomes a fixed token and each '?' an 'x', so the probe matches
    its own pattern whether the policy names one model or a family. A wildcard Region expands to
    the matching configured Regions and a wildcard account to the principal's account. A pattern
    whose resource type is itself a wildcard, or that has no type, cannot be turned into a valid
    ARN and is left to the bundled sample."""
    parts = pattern.split(":", 5)
    if len(parts) != 6:
        return []
    _, partition, service, region, account, resource = parts
    if "/" not in resource:
        return []
    resource_type, name = resource.split("/", 1)
    if _has_wildcard(resource_type):
        return []
    concrete = f"{resource_type}/{name.replace('*', WILDCARD_TOKEN).replace('?', 'x')}"
    partition = "aws" if _has_wildcard(partition) else partition
    account = account_id if _has_wildcard(account) else account
    if _has_wildcard(region):
        selected = [candidate for candidate in regions if iam_matches(region, candidate)]
    else:
        selected = [region]
    return [f"arn:{partition}:{service}:{item}:{account}:{concrete}" for item in selected]


class PolicyResourceReader:
    """Reads a user's inline, managed and group policies for the Amazon Bedrock resources they name.

    One reader serves one account. Managed policy documents and group policies are cached, so a
    policy shared by many users is fetched once."""

    def __init__(self, iam: Any, invoke_actions: Sequence[str]):
        self._iam = iam
        self._invoke = tuple(invoke_actions)
        self._managed: dict[str, list[str]] = {}
        self._group: dict[str, list[str]] = {}

    def resources_for(self, principal: Principal) -> tuple[str, ...]:
        found: dict[str, None] = {}
        for document in self._user_documents(principal.name):
            self._add(found, document)
        for arn in principal.attached_policy_arns:
            for resource in self._managed_resources(arn):
                found.setdefault(resource, None)
        for group in principal.groups:
            for resource in self._group_resources(group):
                found.setdefault(resource, None)
        return tuple(found)

    def _add(self, found: dict[str, None], document: Mapping[str, Any]) -> None:
        for resource in extract_bedrock_resources(document, self._invoke):
            found.setdefault(resource, None)

    def _user_documents(self, user_name: str) -> list[Mapping[str, Any]]:
        documents: list[Mapping[str, Any]] = []
        try:
            for page in self._iam.get_paginator("list_user_policies").paginate(UserName=user_name):
                for name in page["PolicyNames"]:
                    raw = self._iam.get_user_policy(UserName=user_name, PolicyName=name)
                    documents.append(_as_document(raw["PolicyDocument"]))
        except ClientError as exc:
            if not _missing(exc):
                raise
        return documents

    def _managed_resources(self, arn: str) -> list[str]:
        if arn not in self._managed:
            self._managed[arn] = self._read_managed(arn)
        return self._managed[arn]

    def _read_managed(self, arn: str) -> list[str]:
        try:
            version = self._iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            raw = self._iam.get_policy_version(PolicyArn=arn, VersionId=version)
        except ClientError as exc:
            if _missing(exc):
                return []
            raise
        return extract_bedrock_resources(
            _as_document(raw["PolicyVersion"]["Document"]), self._invoke
        )

    def _group_resources(self, group: str) -> list[str]:
        if group not in self._group:
            self._group[group] = self._read_group(group)
        return self._group[group]

    def _read_group(self, group: str) -> list[str]:
        found: dict[str, None] = {}
        try:
            for page in self._iam.get_paginator("list_group_policies").paginate(GroupName=group):
                for name in page["PolicyNames"]:
                    raw = self._iam.get_group_policy(GroupName=group, PolicyName=name)
                    self._add(found, _as_document(raw["PolicyDocument"]))
        except ClientError as exc:
            if not _missing(exc):
                raise
        return list(found)


def _missing(exc: ClientError) -> bool:
    """A user, group or policy deleted during the scan is skipped, not a reason to fail."""
    return exc.response.get("Error", {}).get("Code") == "NoSuchEntity"
