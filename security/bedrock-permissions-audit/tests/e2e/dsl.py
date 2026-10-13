# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""A tiny fixture language for end-to-end scenarios: describe a user in one line, run the real
evaluator against an IAM-rules fake, then build, score and sort findings exactly as a run would.

    run(user("alice", allow=["bedrock:InvokeModel"], unused=200))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from bedrock_permissions_audit.audit import build_findings
from bedrock_permissions_audit.config import Config
from bedrock_permissions_audit.evaluator import SimulatorEvaluator, safe_evaluate
from bedrock_permissions_audit.models import Account, Credential, Finding, Principal
from bedrock_permissions_audit.scoring.ordering import is_visible, sort_findings

from ..evaluator.fake_simulator import FakeIam, Statement, allow, deny

NOW = datetime(2026, 6, 1, tzinfo=UTC)
ACCOUNT = Account(account_id="123456789012", name="workloads")
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
HAIKU = "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"

__all__ = ["ACCOUNT", "ADMIN", "HAIKU", "NOW", "Spec", "allow", "deny", "run", "user", "visible"]


@dataclass
class Spec:
    principal: Principal
    statements: list[Statement] = field(default_factory=list)
    boundary: list[Statement] | None = None


def user(
    name,
    *,
    allow=(),  # noqa: A002 - reads naturally in scenarios
    resources=("*",),
    extra=(),
    deny_actions=(),
    boundary=None,
    policies=(),
    age=10,
    unused=1,  # days since last use; None = never used
    mfa=True,
    active=True,
    phantom=False,
    api_key=False,
    root=False,
    no_credential=False,
) -> Spec:
    statements = list(extra)
    if allow:
        statements.append(_allow(allow, resources))
    if deny_actions:
        statements.append(_deny(deny_actions))

    key_id = f"AKIA{name.upper():0<16}"[:20]
    last_used = None if unused is None else NOW - timedelta(days=unused)
    created = NOW - timedelta(days=age)
    if api_key:
        credential = Credential(
            kind="bedrock_api_key",
            key_id="ABCD1234ABCD1234ABCD1",
            active=active,
            created=created,
            age_days=age,
            last_used_known=False,
        )
    else:
        credential = Credential(
            kind="root_access_key" if root else "access_key",
            key_id="root-access-key-1" if root else key_id,
            active=active,
            created=created,
            last_used=last_used,
            age_days=age,
            unused_days=unused,
        )
    keys = () if no_credential else (credential,)
    principal = Principal(
        account_id=ACCOUNT.account_id,
        name=name,
        arn=f"arn:aws:iam::{ACCOUNT.account_id}:{'root' if root else 'user/' + name}",
        is_root=root,
        mfa_active=mfa,
        access_keys=() if api_key else keys,
        api_keys=keys if api_key else (),
        attached_policy_arns=tuple(policies),
        is_phantom=phantom,
    )
    return Spec(principal, statements, boundary)


def _allow(actions, resources):
    return allow(actions, resources)


def _deny(actions):
    return deny(actions)


def run(*specs: Spec, config: Config | None = None) -> list[Finding]:
    config = config or Config()
    findings: list[Finding] = []
    for spec in specs:
        iam = FakeIam(spec.statements, boundary=spec.boundary)
        evaluation = safe_evaluate(SimulatorEvaluator(iam, config), spec.principal)
        findings.extend(build_findings(ACCOUNT, spec.principal, evaluation, config))
    return sort_findings(findings, config)


def visible(findings: list[Finding], config: Config | None = None) -> list[Finding]:
    config = config or Config()
    return [f for f in findings if is_visible(f, config)]
