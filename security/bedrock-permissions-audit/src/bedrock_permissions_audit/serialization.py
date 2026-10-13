# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Lossless conversion of results to and from plain JSON types, used for checkpoints."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from typing import Any

from .models import (
    Account,
    AccountResult,
    ActionResult,
    Credential,
    Finding,
    Tier,
)


def to_plain(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        attributes = vars(value)
        return {f.name: to_plain(attributes[f.name]) for f in fields(value)}
    if isinstance(value, enum.Enum):
        return value.name
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (tuple, list)):
        return [to_plain(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): to_plain(item) for key, item in value.items()}
    return value


def _time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def credential_from_plain(data: Mapping[str, Any]) -> Credential:
    return Credential(
        kind=data["kind"],
        key_id=data["key_id"],
        active=data["active"],
        created=_time(data.get("created")),
        last_used=_time(data.get("last_used")),
        last_used_region=data.get("last_used_region"),
        age_days=data.get("age_days"),
        unused_days=data.get("unused_days"),
        last_used_known=data.get("last_used_known", True),
        expires=_time(data.get("expires")),
        expired=data.get("expired", False),
    )


def action_result_from_plain(data: Mapping[str, Any]) -> ActionResult:
    return ActionResult(
        action=data["action"],
        decision=data["decision"],
        resource=data["resource"],
        matched_statements=tuple(data.get("matched_statements", ())),
        missing_context=tuple(data.get("missing_context", ())),
    )


def finding_from_plain(data: Mapping[str, Any]) -> Finding:
    credential = data.get("credential")
    return Finding(
        account_id=data["account_id"],
        account_name=data.get("account_name"),
        principal_arn=data["principal_arn"],
        principal_name=data["principal_name"],
        credential=credential_from_plain(credential) if credential else None,
        mfa_active=data.get("mfa_active", False),
        is_root=data.get("is_root", False),
        is_phantom=data.get("is_phantom", False),
        orphaned=data.get("orphaned", False),
        admin_policies=tuple(data.get("admin_policies", ())),
        results=tuple(action_result_from_plain(r) for r in data.get("results", ())),
        grant=data.get("grant", "none"),
        regions_allowed=tuple(data.get("regions_allowed", ())),
        tier=Tier[data.get("tier", "INFO")],
        if_reactivated_tier=Tier[data["if_reactivated_tier"]]
        if data.get("if_reactivated_tier")
        else None,
        tier_reasons=tuple(data.get("tier_reasons", ())),
        recommended_action=data.get("recommended_action", ""),
        warnings=tuple(data.get("warnings", ())),
    )


def account_result_from_plain(data: Mapping[str, Any]) -> AccountResult:
    account = data["account"]
    return AccountResult(
        account=Account(
            account_id=account["account_id"],
            name=account.get("name"),
            is_caller=account.get("is_caller", False),
        ),
        status=data["status"],
        reason=data.get("reason"),
        findings=tuple(finding_from_plain(f) for f in data.get("findings", ())),
        principals_evaluated=data.get("principals_evaluated", 0),
        warnings=tuple(data.get("warnings", ())),
        credential_report_generated_at=_time(data.get("credential_report_generated_at")),
    )
