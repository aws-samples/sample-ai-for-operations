# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Builders for scoring tests. Defaults describe a healthy, MFA-protected, recently used key
that can invoke Amazon Bedrock on any model, so each test changes only what it is about."""

from __future__ import annotations

from bedrock_permissions_audit.models import ActionResult, Credential, Finding

KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS documentation example, not a real key
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
INVOKE = "bedrock:InvokeModel"


def allowed(*actions: str) -> tuple[ActionResult, ...]:
    return tuple(ActionResult(a, "allowed", "*", ("Policy (IAM Policy)",)) for a in actions)


def credential(**overrides) -> Credential:
    values = {
        "kind": "access_key",
        "key_id": KEY_ID,
        "active": True,
        "age_days": 10,
        "unused_days": 1,
        "last_used_known": True,
    }
    values.update(overrides)
    # last_used is a timestamp in real data; for scoring only its presence matters.
    if "last_used" not in values and values["unused_days"] is not None:
        from datetime import UTC, datetime

        values["last_used"] = datetime(2026, 5, 31, tzinfo=UTC)
    return Credential(**values)


def finding(**overrides) -> Finding:
    values = {
        "account_id": "123456789012",
        "account_name": "workloads",
        "principal_arn": "arn:aws:iam::123456789012:user/alice",
        "principal_name": "alice",
        "credential": credential(),
        "mfa_active": True,
        "results": allowed(INVOKE),
        "grant": "broad",
        "regions_allowed": ("us-east-1", "eu-west-1"),
    }
    values.update(overrides)
    return Finding(**values)
