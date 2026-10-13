# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A stand-in for iam.simulate_principal_policy that applies IAM's evaluation rules to a list of
statements: an explicit Deny wins, then an Allow, otherwise implicit deny, and a permissions
boundary must also allow. Resource matching is glob style, as in IAM.

This tests our logic, not IAM's. Fidelity to the real simulator is checked in a sandbox account
(tasks 9.2) and by tests/evaluator/test_response_shapes.py."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from botocore.exceptions import ClientError


@dataclass(frozen=True)
class Statement:
    effect: str  # "Allow" or "Deny"
    actions: tuple[str, ...]
    resources: tuple[str, ...] = ("*",)
    policy: str = "TestPolicy"


def allow(actions, resources=("*",), policy="TestPolicy"):
    return Statement("Allow", tuple(actions), tuple(resources), policy)


def deny(actions, resources=("*",), policy="TestDeny"):
    return Statement("Deny", tuple(actions), tuple(resources), policy)


@dataclass
class FakeIam:
    statements: list[Statement]
    boundary: list[Statement] | None = None
    reject_actions: set[str] = field(default_factory=set)
    raise_error: str | None = None
    calls: list[dict] = field(default_factory=list)
    # Managed policy documents by ARN, for tests that attach a managed policy to the user.
    managed: dict = field(default_factory=dict)
    policy_reads: int = 0

    def get_paginator(self, name):
        if name == "simulate_principal_policy":
            return self
        # The evaluator also reads the user's own policies for the resources they name. The
        # fake's statements stand for the user's effective permissions, so present them as one
        # inline policy.
        pages = {
            "list_user_policies": {"PolicyNames": ["fake-inline"]},
            "list_group_policies": {"PolicyNames": []},
        }
        return _StaticPaginator(pages[name])

    def get_user_policy(self, UserName, PolicyName):  # noqa: N803 - mirrors the boto3 signature
        self.policy_reads += 1
        return {"PolicyDocument": self.document()}

    def get_group_policy(self, GroupName, PolicyName):  # noqa: N803
        self.policy_reads += 1
        return {"PolicyDocument": {"Statement": []}}

    def get_policy(self, PolicyArn):  # noqa: N803
        self.policy_reads += 1
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):  # noqa: N803
        self.policy_reads += 1
        return {"PolicyVersion": {"Document": self.managed.get(PolicyArn, {"Statement": []})}}

    def document(self):
        """The statements as an IAM policy document."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": s.effect,
                    "Action": list(s.actions),
                    "Resource": list(s.resources),
                }
                for s in self.statements
            ],
        }

    def paginate(self, **params):
        self.calls.append(params)
        if self.raise_error:
            raise ClientError(
                {"Error": {"Code": self.raise_error, "Message": self.raise_error}},
                "SimulatePrincipalPolicy",
            )
        rejected = self.reject_actions & set(params["ActionNames"])
        if rejected:
            raise ClientError(
                {"Error": {"Code": "InvalidInput", "Message": f"bad action {sorted(rejected)}"}},
                "SimulatePrincipalPolicy",
            )
        # Observed against the real simulator: with specific resource ARNs, actions that need
        # different authorization information cannot share a call.
        if "ResourceArns" in params and len(_authorization_groups(params["ActionNames"])) > 1:
            raise ClientError(
                {
                    "Error": {
                        "Code": "InvalidInput",
                        "Message": "Actions require different authorization information.",
                    }
                },
                "SimulatePrincipalPolicy",
            )
        resources = params.get("ResourceArns", ["*"])
        results = []
        for action in params["ActionNames"]:
            per_resource = [self._decide(action, resource) for resource in resources]
            item = {"EvalActionName": action, "EvalDecision": _overall(per_resource)}
            if "ResourceArns" in params:
                item["ResourceSpecificResults"] = [
                    {
                        "EvalResourceName": resource,
                        "EvalResourceDecision": decision,
                        "MatchedStatements": [
                            {"SourcePolicyId": policy, "SourcePolicyType": "IAM Policy"}
                            for policy in policies
                        ],
                    }
                    for resource, (decision, policies) in zip(resources, per_resource, strict=True)
                ]
            else:
                item["EvalResourceName"] = "*"
                item["MatchedStatements"] = [
                    {"SourcePolicyId": policy, "SourcePolicyType": "IAM Policy"}
                    for policy in per_resource[0][1]
                ]
            results.append(item)
        yield {"EvaluationResults": results, "IsTruncated": False}

    def _decide(self, action, resource):
        decision, policies = _evaluate(self.statements, action, resource)
        if decision == "allowed" and self.boundary is not None:
            boundary_decision, _ = _evaluate(self.boundary, action, resource)
            if boundary_decision != "allowed":
                return "implicitDeny", []
        return decision, policies


class _StaticPaginator:
    def __init__(self, page):
        self._page = page

    def paginate(self, **_params):
        return iter([self._page])


def statements_from_document(document, policy="Managed"):
    """Turn an IAM policy document into fake-simulator statements, so a real managed policy
    document can be evaluated by the rule-faithful fake."""
    statements = document["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    result = []
    for item in statements:
        actions = item["Action"] if isinstance(item["Action"], list) else [item["Action"]]
        resources = item["Resource"] if isinstance(item["Resource"], list) else [item["Resource"]]
        result.append(Statement(item["Effect"], tuple(actions), tuple(resources), policy))
    return result


def _evaluate(statements, action, resource):
    denying = _matching(statements, "Deny", action, resource)
    if denying:
        return "explicitDeny", denying
    allowing = _matching(statements, "Allow", action, resource)
    if allowing:
        return "allowed", allowing
    return "implicitDeny", []


def _matching(statements, effect, action, resource):
    return [
        s.policy
        for s in statements
        if s.effect == effect
        and any(fnmatchcase(action.lower(), pattern.lower()) for pattern in s.actions)
        and any(fnmatchcase(resource, pattern) for pattern in s.resources)
    ]


def _overall(per_resource):
    """The real simulator reports the most restrictive decision across the resources: one denied
    resource makes the overall decision a deny. Per-resource results carry the detail."""
    decisions = {decision for decision, _ in per_resource}
    if "explicitDeny" in decisions:
        return "explicitDeny"
    if "implicitDeny" in decisions:
        return "implicitDeny"
    return "allowed"


# Compatible groups measured against the real simulator. Anything not listed stands alone.
AUTHORIZATION_GROUPS = (
    {
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:CallWithBearerToken",
        "bedrock-mantle:CallWithBearerToken",
    },
    {"bedrock:Converse", "bedrock:ConverseStream"},
)


def _authorization_groups(actions):
    groups = set()
    for action in actions:
        match = next((i for i, group in enumerate(AUTHORIZATION_GROUPS) if action in group), None)
        groups.add(match if match is not None else action)
    return groups
