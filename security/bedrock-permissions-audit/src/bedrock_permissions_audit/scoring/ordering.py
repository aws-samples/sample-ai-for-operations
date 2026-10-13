# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Ordering of findings. Within a tier the order is: inactive keys that would rate Critical if
re-enabled, then those that would rate High, then everything else (only Low can hold such keys);
then root first, dormant before active (a credential no workload uses is the least likely to be
noticed if used unexpectedly), older before newer, and wider before narrower."""

from __future__ import annotations

from ..config import Config
from ..models import Finding, Tier


def _reactivation_rank(finding: Finding) -> int:
    """0 for an inactive key that would rate Critical if re-enabled, 1 for High, 2 otherwise."""
    if finding.if_reactivated_tier is Tier.CRITICAL:
        return 0
    if finding.if_reactivated_tier is Tier.HIGH:
        return 1
    return 2


def sort_key(finding: Finding, config: Config) -> tuple[int, int, int, int, int, int, str, str]:
    credential = finding.credential
    dormant = credential is not None and credential.is_dormant(config.dormant_days)
    age = credential.age_days if credential is not None and credential.age_days else 0
    return (
        int(finding.tier),
        _reactivation_rank(finding),
        # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
        0 if finding.is_root else 1,
        0 if dormant else 1,
        -age,
        -len(finding.regions_allowed),
        finding.account_id,
        finding.principal_name,
    )


def sort_findings(findings: list[Finding], config: Config) -> list[Finding]:
    return sorted(findings, key=lambda finding: sort_key(finding, config))


CANNOT_INVOKE = "cannot_invoke"
INACTIVE_OR_EXPIRED = "inactive_or_expired"


def hidden_reason(finding: Finding) -> str:
    """Why an Info finding is Info. Read from the credential, the same field `tiers.assign` reads,
    so the two cannot drift: no credential, or one that is inactive or expired, is
    `inactive_or_expired`; an active credential that is Info cannot invoke Amazon Bedrock."""
    credential = finding.credential
    if credential is None or not credential.active:
        return INACTIVE_OR_EXPIRED
    return CANNOT_INVOKE


def is_visible(finding: Finding, config: Config) -> bool:
    """Info rows are hidden unless --all, with one exception: a principal whose permissions
    could not be evaluated is always shown, because hiding it would make a gap look clean."""
    return finding.tier != Tier.INFO or config.show_all or finding.grant == "unknown"
