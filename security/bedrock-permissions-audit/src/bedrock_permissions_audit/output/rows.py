# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Turn findings into flat, display-ready rows shared by the terminal table and the CSV."""

from __future__ import annotations

import re

from ..config import Config
from ..log import redact
from ..models import Finding
from ..scoring.tiers import canary_allowed

CSV_COLUMNS = (
    "tier",
    "account_id",
    "account_name",
    "principal",
    "principal_arn",
    "credential_type",
    "key_id",
    "key_active",
    "key_age_days",
    "last_used_days",
    "last_used_region",
    "mfa",
    "grant",
    "regions_allowed",
    "bedrock_actions_allowed",
    "granting_policies",
    "admin_policies",
    "reasons",
    "recommended_action",
    "warnings",
    "if_reactivated_tier",
)

CREDENTIAL_LABELS = {
    "access_key": "access key",
    "root_access_key": "root access key",
    "bedrock_api_key": "Amazon Bedrock API key",
    "claude_api_key": "Claude Platform API key",
}

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def clean(value: object) -> str:
    """Strip control characters, so no value can inject terminal escape sequences."""
    return _CONTROL.sub("", str(value))


def csv_safe(value: str) -> str:
    """Neutralise spreadsheet formulas. IAM user names may legally start with = + - or @, so a
    user named '=HYPERLINK(...)' would otherwise run when the file is opened in Excel."""
    text = clean(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def key_label(finding: Finding, config: Config) -> str:
    credential = finding.credential
    if credential is None:
        return ""
    return credential.key_id if config.unmask else credential.id_masked


def last_used_text(finding: Finding) -> str:
    credential = finding.credential
    if credential is None or not credential.last_used_known:
        return "unknown"
    if credential.last_used is None:
        return "never"
    return f"{credential.unused_days}d ago"


def actions_allowed(finding: Finding, config: Config) -> tuple[str, ...]:
    interesting = set(config.invoke_actions) | set(config.escalation_actions)
    seen: dict[str, None] = {}
    for result in finding.results:
        if result.decision == "allowed" and result.action in interesting:
            seen.setdefault(result.action, None)
    if canary_allowed(finding, config):
        seen.setdefault("bedrock:* (effective)", None)
    return tuple(seen)


def csv_row(finding: Finding, config: Config) -> dict[str, str]:
    credential = finding.credential
    return {
        "tier": finding.tier.label,
        "account_id": finding.account_id,
        "account_name": finding.account_name or "",
        "principal": finding.principal_name,
        "principal_arn": finding.principal_arn,
        "credential_type": CREDENTIAL_LABELS.get(credential.kind, "") if credential else "none",
        "key_id": key_label(finding, config),
        "key_active": ("yes" if credential.active else "no") if credential else "",
        "key_age_days": str(credential.age_days)
        if credential and credential.age_days is not None
        else "",
        "last_used_days": last_used_text(finding),
        "last_used_region": (credential.last_used_region or "") if credential else "",
        "mfa": "yes" if finding.mfa_active else "no",
        "grant": finding.grant,
        "regions_allowed": ";".join(finding.regions_allowed),
        "bedrock_actions_allowed": ";".join(actions_allowed(finding, config)),
        "granting_policies": ";".join(finding.granting_policies),
        "admin_policies": ";".join(finding.admin_policies),
        "reasons": " ".join(finding.tier_reasons),
        "recommended_action": finding.recommended_action,
        "warnings": " ".join(finding.warnings),
        # Tier is an IntEnum and CRITICAL is 0, so test for None, not truthiness.
        "if_reactivated_tier": (
            "" if finding.if_reactivated_tier is None else finding.if_reactivated_tier.label
        ),
    }


def protect(text: str, config: Config) -> str:
    """Last line of defence for free text: nothing shaped like an access key ID leaves the
    process unmasked unless the user asked for --unmask."""
    return text if config.unmask else redact(text)
