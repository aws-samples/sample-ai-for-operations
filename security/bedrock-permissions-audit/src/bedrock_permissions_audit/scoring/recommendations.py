# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""One recommended action per finding, chosen by rule. Text only: the tool never acts on it."""

from __future__ import annotations

from ..config import Config
from ..models import Credential, Finding, Tier
from .tiers import API_KEY_KINDS, canary_allowed, escalation_actions_allowed

BEARER_DENY = "bedrock:CallWithBearerToken and bedrock-mantle:CallWithBearerToken"


def for_finding(finding: Finding, config: Config) -> str:
    credential = finding.credential

    # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
    if finding.is_root:
        if credential is not None and credential.active:
            return (
                "Delete the root access key. Use IAM Identity Center or IAM roles for "
                "day-to-day work and keep root for account-level tasks only."
            )
        return "Delete the inactive root access key; root should have no access keys."

    if finding.orphaned:
        return (
            f"Delete the IAM user {finding.principal_name}. It holds no active credential, "
            "and any policy attached to it is a standing risk."
        )

    if finding.grant == "unknown":
        return "Review this principal manually: its permissions could not be evaluated."

    if credential is None:
        return "No action needed for Amazon Bedrock exposure."
    if not credential.active:
        return _inactive_key(finding, credential)

    if finding.tier == Tier.INFO:
        return "No action needed for Amazon Bedrock exposure."

    label = credential.id_masked

    if credential.kind in API_KEY_KINDS:
        return (
            f"Delete or rotate the API key {label} on {finding.principal_name}. If API keys "
            f"are not needed, deny {BEARER_DENY} for this user."
        )

    if credential.is_dormant(config.dormant_days):
        history = (
            "never used" if credential.never_used else f"unused for {credential.unused_days} days"
        )
        return f"Delete access key {label} ({history}). Recreate it only if a workload breaks."

    escalation = escalation_actions_allowed(finding, config)
    if escalation:
        return (
            f"Remove {', '.join(escalation)} from {finding.principal_name}'s policies, then "
            f"rotate access key {label} and move the workload to an IAM role."
        )

    if finding.admin_policies or canary_allowed(finding, config):
        return (
            f"Replace the broad permissions on {finding.principal_name} with a policy limited "
            f"to the Amazon Bedrock actions, models and Regions it needs, and rotate access "
            f"key {label}."
        )

    if not finding.mfa_active or _is_old(credential, config):
        return (
            f"Move the workload behind {finding.principal_name} to an IAM role so no long-lived "
            f"key exists. If the user must stay, rotate access key {label} and enable MFA."
        )

    if finding.tier == Tier.LOW:
        return (
            "No urgent action. Prefer an IAM role over a long-lived key and keep the policy "
            "scoped to the models and Regions in use."
        )

    return (
        f"Limit {finding.principal_name} to the specific models and Regions it needs, and "
        "prefer an IAM role over a long-lived key."
    )


def _inactive_key(finding: Finding, credential: Credential) -> str:
    """Advice for a credential that is inactive or expired."""
    if finding.grant == "none":
        return "No action needed for Amazon Bedrock exposure."

    label = credential.id_masked
    admin = ", including admin-class permissions" if finding.admin_policies else ""
    if credential.kind in API_KEY_KINDS:
        # IAM does not report when an API key was last used, so do not say it is unused.
        if finding.if_reactivated_tier is not None:
            return (
                f"Delete inactive API key {label} on {finding.principal_name}. Re-enabling it "
                f"would restore Amazon Bedrock access{admin}."
            )
        state = "expired" if credential.expired else "inactive"
        return (
            f"Delete the {state} API key {label} on {finding.principal_name}; "
            "it has no reason to exist."
        )
    if finding.if_reactivated_tier is not None:
        return (
            f"Delete inactive access key {label} on {finding.principal_name}. It is unused, and "
            f"re-enabling it would restore Amazon Bedrock access{admin}."
        )
    return f"Delete inactive access key {label}; it has no reason to exist."


def _is_old(credential: Credential, config: Config) -> bool:
    return credential.age_days is not None and credential.age_days >= config.dormant_days
