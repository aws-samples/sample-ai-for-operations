# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""Tier assignment. Pure functions: no AWS, no I/O, so every rule is testable on its own.

Rules apply in this order and the first match wins:

  1. Root account                                                -> Critical if its key is active
  2. Orphaned API key user (no active credential left)           -> Medium
  3. Inactive IAM access key or API key that would rate Critical
     or High if it were re-enabled (its secret still works)    -> Low
     Any other inactive or expired credential                    -> Info
  4. Permissions could not be evaluated                          -> Info (shown, never hidden)
  5. Can invoke Amazon Bedrock and holds an admin-class policy,
     the canary action, or an escalation action                  -> Critical
  6. Can invoke and the key is dormant or old, or (for access
     keys) the user has no MFA                                   -> High
  7. API key on a phantom user, unless the simulator found
     no access at all                                            -> High
  8. Can invoke with a broad grant                               -> Medium
  9. Can invoke with a scoped grant                              -> Low
 10. Anything else                                               -> Info
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..config import Config
from ..models import Credential, Finding, Tier

API_KEY_KINDS = ("bedrock_api_key", "claude_api_key")


INACTIVE_REASON = "The credential is inactive or expired and cannot be used."
REENABLE_REASON = (
    "The key is inactive but its secret works again if anyone re-enables it with "
    "iam:UpdateAccessKey."
)
REENABLE_API_KEY_REASON = (
    "The key is inactive but works again if anyone re-enables it with "
    "iam:UpdateServiceSpecificCredential."
)


# Introduces the inner reasons of an inactive key; the terminal indents what follows it.
WOULD_RATE_PREFIX = "If re-enabled it would rate "


@dataclass(frozen=True)
class TierResult:
    tier: Tier
    reasons: tuple[str, ...]
    # Set only for an inactive access key reported as Low: the tier it would get if re-enabled.
    if_reactivated: Tier | None = None


def allowed_actions(finding: Finding) -> frozenset[str]:
    return frozenset(r.action for r in finding.results if r.decision == "allowed")


def can_invoke(finding: Finding, config: Config) -> bool:
    return bool(allowed_actions(finding) & set(config.invoke_actions))


def escalation_actions_allowed(finding: Finding, config: Config) -> tuple[str, ...]:
    allowed = allowed_actions(finding)
    return tuple(a for a in config.escalation_actions if a in allowed)


def canary_allowed(finding: Finding, config: Config) -> bool:
    """True when every canary action is allowed on '*', which means effectively bedrock:*.

    All of them, not any: a single management action is granted by narrower managed policies, so one
    allowed action says nothing. An empty list never claims bedrock:*."""
    canary = set(config.canary_actions)
    return bool(canary) and canary <= allowed_actions(finding)


def assign(finding: Finding, config: Config) -> TierResult:
    credential = finding.credential

    # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
    if finding.is_root:
        if credential is not None and credential.active:
            return TierResult(Tier.CRITICAL, ("The root account has an active access key.",))
        return TierResult(Tier.INFO, ("The root access key is inactive.",))

    if finding.orphaned:
        return TierResult(
            Tier.MEDIUM,
            ("This API key user has no active credential left but was never cleaned up.",),
        )

    if credential is None:
        return TierResult(Tier.INFO, (INACTIVE_REASON,))
    if not credential.active:
        return _inactive_key(finding, credential, config)

    if finding.grant == "unknown":
        return TierResult(
            Tier.INFO, ("Permissions could not be evaluated; review this principal manually.",)
        )

    invoke = can_invoke(finding, config)
    if invoke:
        critical = _critical_reasons(finding, config)
        if critical:
            return TierResult(Tier.CRITICAL, ("Can invoke Amazon Bedrock models.", *critical))

        high = _high_reasons(finding, credential, config)
        if high:
            return TierResult(Tier.HIGH, ("Can invoke Amazon Bedrock models.", *high))

    # nosemgrep: is-function-without-parentheses -- bool dataclass field, not a function
    if finding.is_phantom and credential.kind in API_KEY_KINDS and finding.grant != "none":
        return TierResult(
            Tier.HIGH,
            ("An Amazon Bedrock API key is a bearer token that works from anywhere.",),
        )

    if invoke and finding.grant == "broad":
        # IAM does not report when an API key was last used, so do not claim it is in use.
        recency = (
            "the key is recent and in use"
            if credential.last_used_known
            else "the key is recent (IAM does not report when an API key was last used)"
        )
        return TierResult(Tier.MEDIUM, (f"Can invoke any model in any Region; {recency}.",))
    if invoke and finding.grant == "scoped":
        return TierResult(
            Tier.LOW, (f"Can invoke only specific models or Regions ({_regions(finding)}).",)
        )
    return TierResult(Tier.INFO, ("Cannot invoke Amazon Bedrock models.",))


def _inactive_key(finding: Finding, credential: Credential, config: Config) -> TierResult:
    """Rate an inactive credential.

    Deactivating an access key does not invalidate its secret: anyone who can call
    iam:UpdateAccessKey on the user can re-enable it, and it then works with the same
    permissions. So rate the key as if it were active, by running these same rules on a copy, and
    surface it when that would be Critical or High. Reusing the rules keeps the two from drifting.

    IAM access keys and Amazon Bedrock or Claude Platform API keys are re-evaluated (an API key is
    re-enabled with iam:UpdateServiceSpecificCredential). Expired credentials cannot be re-enabled
    and stay Info. Nothing here needs AWS; it uses only data already collected."""
    if not credential.expired and (
        credential.kind == "access_key" or credential.kind in API_KEY_KINDS
    ):
        reactivated = assign(replace(finding, credential=replace(credential, active=True)), config)
        if reactivated.tier in (Tier.CRITICAL, Tier.HIGH):
            return TierResult(
                Tier.LOW,
                (
                    _reenable_reason(credential),
                    f"{WOULD_RATE_PREFIX}{reactivated.tier.label}:",
                    *reactivated.reasons,
                ),
                if_reactivated=reactivated.tier,
            )
    return TierResult(Tier.INFO, (INACTIVE_REASON,))


def _reenable_reason(credential: Credential) -> str:
    if credential.kind in API_KEY_KINDS:
        return REENABLE_API_KEY_REASON
    return REENABLE_REASON


def _critical_reasons(finding: Finding, config: Config) -> list[str]:
    reasons: list[str] = []
    if finding.admin_policies:
        names = ", ".join(_policy_name(arn) for arn in finding.admin_policies)
        reasons.append(f"Holds an admin-class policy: {names}.")
    if canary_allowed(finding, config):
        reasons.append("Effectively holds bedrock:* (full control of Amazon Bedrock).")
    escalation = escalation_actions_allowed(finding, config)
    if escalation:
        reasons.append(
            "Can also enable more models or create new API keys: " + ", ".join(escalation) + "."
        )
    return reasons


def _high_reasons(finding: Finding, credential: Credential, config: Config) -> list[str]:
    threshold = config.dormant_days
    reasons: list[str] = []
    if credential.is_dormant(threshold):
        if credential.never_used:
            reasons.append("The key has never been used, so nobody would notice misuse.")
        else:
            reasons.append(
                f"The key has not been used for {credential.unused_days} days "
                f"(threshold {threshold})."
            )
    if credential.age_days is not None and credential.age_days >= threshold:
        reasons.append(f"The key is {credential.age_days} days old (threshold {threshold}).")
    # MFA protects console sign-in and MFA-conditioned policies; it does nothing for a bearer token.
    if credential.kind == "access_key" and not finding.mfa_active:
        reasons.append("The user has no MFA device.")
    return reasons


def _regions(finding: Finding) -> str:
    return ", ".join(finding.regions_allowed) if finding.regions_allowed else "none found"


def _policy_name(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]
