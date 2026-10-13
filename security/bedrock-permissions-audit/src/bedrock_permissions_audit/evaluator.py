# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Decide what a principal is allowed to do with Amazon Bedrock, using the IAM policy simulator.

Passes, in order (each costs a handful of calls, so 100 users stay in the low hundreds):

  1. Every configured action against resource "*". An allowed invoke action means a statement
     with Resource "*" grants it: a broad grant.
  2. IAM escalation actions (such as iam:CreateServiceSpecificCredential) against the
     principal's own ARN. These are normally granted on a specific user, so "*" would miss them,
     and a key that can create its own API key is an escalation path.
  3. Only if pass 1 allowed no invoke action: the invoke actions against a grid of sample model
     and inference-profile ARNs. If most are allowed (for example a policy on
     arn:aws:bedrock:*::foundation-model/*) the grant is effectively broad; if only some are,
     it is scoped, and the allowed Regions are recorded.

The simulator does not evaluate Service Control Policies."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

from .collectors.policy_resources import PolicyResourceReader, probe_arns
from .config import Config, bundled_region_data, effective_models, effective_regions
from .models import ActionResult, Grant, Principal

logger = logging.getLogger(__name__)

# Share of probed ARNs that must be allowed for a grant to count as broad.
BROAD_SHARE = 0.8
# ResourceArns per SimulatePrincipalPolicy call.
RESOURCE_CHUNK = 25
ROOT_STATEMENT = "account root (unrestricted)"
# Most extra probe ARNs built from a user's own policies, so one oddly broad policy cannot make a
# single principal cost hundreds of calls.
MAX_POLICY_PROBES = 120


@dataclass(frozen=True)
class Evaluation:
    results: tuple[ActionResult, ...]
    grant: Grant
    regions_allowed: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class Evaluator(Protocol):
    def evaluate(self, principal: Principal) -> Evaluation: ...


def evaluate_root(config: Config) -> Evaluation:
    """The root user is not subject to IAM policies, so it is modelled as allowed everywhere."""
    return Evaluation(
        results=tuple(
            ActionResult(action, "allowed", "*", (ROOT_STATEMENT,)) for action in config.all_actions
        ),
        grant="broad",
        regions_allowed=effective_regions(config),
    )


PERMISSION_ERRORS = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "ExpiredToken",
    "ExpiredTokenException",
}


def safe_evaluate(evaluator: Evaluator, principal: Principal) -> Evaluation:
    """Keep one awkward principal from aborting the account.

    A transient or per-principal failure (throttling that outlasted the retries, a user deleted
    mid-scan) becomes grant='unknown' with a warning, and scoring never hides unknown rows.
    A permission or credential error is re-raised: it would hit every principal, and turning a
    broken audit into a page of quiet 'unknown' rows would look like a clean result."""
    try:
        return evaluator.evaluate(principal)
    except ClientError as exc:
        code = _code(exc) or "Error"
        if code in PERMISSION_ERRORS:
            raise
        return _unknown(principal, code)
    except BotoCoreError as exc:
        return _unknown(principal, type(exc).__name__)


def _unknown(principal: Principal, reason: str) -> Evaluation:
    logger.warning("simulation_failed", extra={"principal": principal.name, "error": reason})
    return Evaluation(
        results=(),
        grant="unknown",
        warnings=(f"Could not evaluate {principal.name}: {reason}. Review it manually.",),
    )


class SimulatorEvaluator:
    def __init__(self, iam: Any, config: Config, policy_reader: PolicyResourceReader | None = None):
        self._iam = iam
        self._config = config
        self._regions = effective_regions(config)
        self._models = effective_models(config)
        self._profiles = tuple(bundled_region_data().get("representative_inference_profiles", ()))
        self._group_cache: dict[tuple[str, ...], list[list[str]]] = {}
        # Reads the user's own policies for the resources they name. Created per account, so the
        # managed and group policies it caches are shared by every user in that account.
        self._reader = policy_reader or PolicyResourceReader(iam, config.invoke_actions)

    def evaluate(self, principal: Principal) -> Evaluation:
        # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
        if principal.is_root:
            return evaluate_root(self._config)

        warnings: list[str] = []
        results, notes = self._simulate(principal.arn, self._config.all_actions, ["*"])
        warnings.extend(notes)

        self_actions = [a for a in self._config.escalation_actions if a.startswith("iam:")]
        already_allowed = {r.action for r in results if r.decision == "allowed"}
        pending = [a for a in self_actions if a not in already_allowed]
        if pending:
            own, notes = self._simulate(principal.arn, pending, [principal.arn])
            results.extend(own)
            warnings.extend(notes)

        invoke = set(self._config.invoke_actions)
        if any(r.decision == "allowed" and r.action in invoke for r in results):
            return Evaluation(tuple(results), "broad", self._regions, tuple(warnings))

        # No broad grant. A fixed sample cannot know every model, so also test the resources the
        # user's own policies name: a policy that allows only a model outside the sample is found.
        named = self._reader.resources_for(principal)
        named_probes, truncated = self._policy_probes(named, principal.account_id)
        if truncated:
            warnings.append(
                f"{principal.name}: the policies name more Amazon Bedrock resources than the "
                f"{MAX_POLICY_PROBES} the audit tests, so some were not tested."
            )
        probes = list(dict.fromkeys([*self._probe_arns(principal.account_id), *named_probes]))
        probed, notes = self._simulate(principal.arn, self._config.invoke_actions, probes)
        warnings.extend(notes)
        results.extend(probed)

        allowed = {r.resource for r in probed if r.decision == "allowed"}
        if not allowed:
            if named and not self._explicitly_denied(probed, named_probes or probes):
                # An Allow names Amazon Bedrock resources and every one was denied without an
                # explicit deny: a condition, a permissions boundary or an unlisted action may be
                # hiding access. Say so, rather than call the principal harmless.
                warnings.append(
                    f"{principal.name}: a policy allows Amazon Bedrock resources, but the "
                    "simulator denied every one without an explicit deny (a condition or a "
                    "permissions boundary may apply). Review it manually."
                )
                return Evaluation(tuple(results), "unknown", (), tuple(warnings))
            return Evaluation(tuple(results), "none", (), tuple(warnings))

        grant: Grant = "broad" if len(allowed) / len(probes) >= BROAD_SHARE else "scoped"
        regions = tuple(sorted({arn.split(":")[3] for arn in allowed} - {""}))
        return Evaluation(tuple(results), grant, regions, tuple(warnings))

    def _policy_probes(self, patterns: Sequence[str], account_id: str) -> tuple[list[str], bool]:
        """Concrete ARNs for the resources the user's policies name, capped. Returns the probes and
        whether the cap cut any off."""
        probes: dict[str, None] = {}
        for pattern in patterns:
            for arn in probe_arns(pattern, self._regions, account_id):
                probes.setdefault(arn, None)
        ordered = list(probes)
        return ordered[:MAX_POLICY_PROBES], len(ordered) > MAX_POLICY_PROBES

    @staticmethod
    def _explicitly_denied(results: Sequence[ActionResult], resources: Sequence[str]) -> bool:
        """An explicit deny on the resources the policies name is a definite 'no'. An implicit deny
        is not: it may be a condition or a boundary that the simulator cannot see through."""
        wanted = set(resources)
        return any(r.decision == "explicitDeny" and r.resource in wanted for r in results)

    def _probe_arns(self, account_id: str) -> list[str]:
        """Sample ARNs: one model in every Region, every model in the home Region, plus
        inference profiles and the other resource types a policy might name."""
        home = "us-east-1" if "us-east-1" in self._regions else self._regions[0]
        first = self._models[0]
        probes = [f"arn:aws:bedrock:{region}::foundation-model/{first}" for region in self._regions]
        probes += [f"arn:aws:bedrock:{home}::foundation-model/{m}" for m in self._models[1:]]
        for profile in self._profiles:
            region = self._profile_region(profile, home)
            probes.append(f"arn:aws:bedrock:{region}:{account_id}:inference-profile/{profile}")
        for resource_type in ("application-inference-profile", "provisioned-model"):
            probes.append(f"arn:aws:bedrock:{home}:{account_id}:{resource_type}/audit-probe")
        return list(dict.fromkeys(probes))

    def _profile_region(self, profile: str, home: str) -> str:
        wanted = "eu-" if profile.startswith("eu.") else "us-"
        return next((r for r in self._regions if r.startswith(wanted)), home)

    def _simulate(
        self, arn: str, actions: Sequence[str], resources: Sequence[str]
    ) -> tuple[list[ActionResult], list[str]]:
        results: list[ActionResult] = []
        warnings: list[str] = []
        # Against "*" the simulator accepts any mix of actions. Against specific resource ARNs it
        # rejects actions that need different authorization information in the same call, so
        # those are batched by compatible group.
        groups = [list(actions)] if list(resources) == ["*"] else self._groups(arn, actions)
        for group in groups:
            for chunk in _chunks(resources, RESOURCE_CHUNK):
                try:
                    results.extend(self._call(arn, group, chunk))
                except ClientError as exc:
                    if _code(exc) != "InvalidInput":
                        raise
                    # Last resort: retry singly to find the rejected name and keep the rest.
                    for action in group:
                        try:
                            results.extend(self._call(arn, [action], chunk))
                        except ClientError as single:
                            if _code(single) != "InvalidInput":
                                raise
                            note = f"The IAM simulator rejected {action}; it was not evaluated."
                            if note not in warnings:
                                warnings.append(note)
        return results, warnings

    def _groups(self, arn: str, actions: Sequence[str]) -> list[list[str]]:
        """Partition actions into groups the simulator accepts together with resource ARNs.

        Learned by probing with one sample ARN, once per evaluator, instead of hard-coding which
        actions are compatible: AWS decides that and it can change."""
        key = tuple(actions)
        if key in self._group_cache:
            return self._group_cache[key]
        probe = [f"arn:aws:bedrock:{self._regions[0]}::foundation-model/{self._models[0]}"]
        groups: list[list[str]] = []
        for action in actions:
            for group in groups:
                if self._accepts(arn, [*group, action], probe):
                    group.append(action)
                    break
            else:
                groups.append([action])
        self._group_cache[key] = groups
        return groups

    def _accepts(self, arn: str, actions: Sequence[str], resources: Sequence[str]) -> bool:
        try:
            self._call(arn, actions, resources)
        except ClientError as exc:
            if _code(exc) == "InvalidInput":
                return False
            raise
        return True

    def _call(
        self, arn: str, actions: Sequence[str], resources: Sequence[str]
    ) -> list[ActionResult]:
        params: dict[str, Any] = {"PolicySourceArn": arn, "ActionNames": list(actions)}
        if list(resources) != ["*"]:
            params["ResourceArns"] = list(resources)
        parsed: list[ActionResult] = []
        for page in self._iam.get_paginator("simulate_principal_policy").paginate(**params):
            for item in page["EvaluationResults"]:
                parsed.extend(_parse(item))
        return parsed


def _parse(item: Mapping[str, Any]) -> Iterator[ActionResult]:
    action = item["EvalActionName"]
    specifics = item.get("ResourceSpecificResults")
    if specifics:
        for specific in specifics:
            yield ActionResult(
                action=action,
                decision=specific["EvalResourceDecision"],
                resource=specific["EvalResourceName"],
                matched_statements=_matched(specific),
                missing_context=tuple(specific.get("MissingContextValues", ())),
            )
    else:
        yield ActionResult(
            action=action,
            decision=item["EvalDecision"],
            resource=item.get("EvalResourceName", "*"),
            matched_statements=_matched(item),
            missing_context=tuple(item.get("MissingContextValues", ())),
        )


def _matched(item: Mapping[str, Any]) -> tuple[str, ...]:
    """Name the policy that matched, never its content."""
    labels: dict[str, None] = {}
    for statement in item.get("MatchedStatements", ()):
        policy = statement.get("SourcePolicyId", "unknown")
        kind = statement.get("SourcePolicyType", "?")
        line = statement.get("StartPosition", {}).get("Line")
        labels[f"{policy} ({kind})" + (f" line {line}" if line else "")] = None
    return tuple(labels)


def _chunks(items: Sequence[str], size: int) -> Iterable[Sequence[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")
