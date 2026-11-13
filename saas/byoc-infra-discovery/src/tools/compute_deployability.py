# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Precision tool: deterministic deployability verdict.

Pure code, no LLM. Applies fixed rules over a collected facts bundle to produce
a verdict of "ready", "degraded", or "blocked" plus the list of blockers. The
agent LLM MUST use this verdict verbatim and only phrase the human reason
strings — it must never compute the verdict itself.
"""

from strands import tool

VERDICT_READY = "ready"
VERDICT_DEGRADED = "degraded"
VERDICT_BLOCKED = "blocked"

_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}

# Each blocker: code -> (severity, default human reason). severity "blocking"
# forces "blocked"; severity "degraded" only downgrades from "ready".
_BLOCKER_REASONS = {
    "region-does-not-exist": "The region does not exist in AWS global infrastructure.",
    "ec2-not-available-in-region": "Amazon EC2 is not available in this region.",
    "eks-not-available-in-region": "Amazon EKS is not available in this region.",
    "no-ami-published": (
        "No matching AMI is published in this region; the node image "
        "(and any EKS API-server proxy that depends on it) cannot be provisioned."
    ),
    "no-eks-ecr-registry-mapped": (
        "No Amazon EKS add-on ECR registry is mapped for this region."
    ),
    "insufficient-azs": "Fewer than two availability zones are available.",
    "instance-type-not-offered": (
        "The requested instance type is not offered in this region."
    ),
}

# When an offering fact comes only from the AWS Price List API (because the
# region is not enabled and the authoritative describe-instance-type-offerings
# call could not be made), a "not offered" result is unconfirmed and must not
# be reported at high confidence.
_PRICING_ONLY_CAVEAT = (
    " Based on the AWS Price List API only; the region is not enabled, so this "
    "could not be confirmed with describe-instance-type-offerings."
)
_BLOCKING_CODES = {
    "region-does-not-exist",
    "ec2-not-available-in-region",
    "eks-not-available-in-region",
    "no-ami-published",
    "instance-type-not-offered",
}


def _lowest_confidence(confidences: list) -> str:
    present = [c for c in confidences if c in _CONFIDENCE_ORDER]
    if not present:
        return "high"
    return min(present, key=lambda c: _CONFIDENCE_ORDER[c])


def compute_deployability_impl(facts: dict) -> dict:
    """Core logic (testable without the Strands runtime).

    Args:
        facts: {
          "region_exists": bool,
          "ec2_available": bool,
          "eks_required": bool,       # whether EKS is part of the target
          "eks_available": bool,
          "ami_available": bool,
          "eks_ecr_registry_present": bool,
          "az_count": int,
          "instance_type_required": bool,
          "instance_type_offered": bool,
          "instance_type_offered_source": str,  # e.g. "pricing-api" | "ec2-live"
          "source_confidences": [ ... ],  # confidence labels from the facts
        }
    """
    if not isinstance(facts, dict):
        return {
            "error": True,
            "error_type": "invalid_input",
            "message": "facts must be a dict",
        }

    blockers: list[dict] = []
    # Confidence ceilings contributed by individual blockers (e.g. an
    # unconfirmed Pricing-only "not offered" caps the overall confidence).
    confidence_caps: list[str] = []

    def add(code: str, reason_suffix: str = "") -> None:
        blockers.append(
            {
                "code": code,
                "severity": "blocking" if code in _BLOCKING_CODES else "degraded",
                "reason": _BLOCKER_REASONS.get(code, code) + reason_suffix,
            }
        )

    if not facts.get("region_exists", True):
        add("region-does-not-exist")
    if not facts.get("ec2_available", True):
        add("ec2-not-available-in-region")
    if facts.get("eks_required") and not facts.get("eks_available", True):
        add("eks-not-available-in-region")
    if not facts.get("ami_available", True):
        add("no-ami-published")
    if facts.get("instance_type_required") and not facts.get("instance_type_offered", True):
        # A "not offered" result sourced only from the Price List API cannot be
        # confirmed for a non-enabled region; mark it unconfirmed and cap the
        # overall verdict confidence so automation does not over-trust it.
        if facts.get("instance_type_offered_source") == "pricing-api":
            add("instance-type-not-offered", reason_suffix=_PRICING_ONLY_CAVEAT)
            confidence_caps.append("medium")
        else:
            add("instance-type-not-offered")
    if facts.get("eks_required") and not facts.get("eks_ecr_registry_present", True):
        add("no-eks-ecr-registry-mapped")
    az_count = facts.get("az_count")
    if isinstance(az_count, int) and az_count < 2:
        add("insufficient-azs")

    if any(b["severity"] == "blocking" for b in blockers):
        verdict = VERDICT_BLOCKED
    elif blockers:
        verdict = VERDICT_DEGRADED
    else:
        verdict = VERDICT_READY

    confidence = _lowest_confidence(
        list(facts.get("source_confidences", [])) + confidence_caps
    )
    return {"verdict": verdict, "blockers": blockers, "confidence": confidence}


@tool
def compute_deployability(facts: dict) -> dict:
    """Compute a deterministic deployability verdict from a facts bundle.

    Returns "blocked" if any blocking condition holds (region missing, Amazon EC2
    or Amazon EKS unavailable, no AMI published, requested instance type not
    offered), "degraded" if only non-blocking issues exist (no EKS ECR registry
    mapped, fewer than two AZs), otherwise "ready". You MUST use the verdict
    returned here verbatim and never compute it yourself.

    Pass "instance_type_offered_source" with the source that produced the
    offering fact (e.g. "pricing-api" or "ec2-live"). When an instance type is
    "not offered" and the source is "pricing-api", the result is unconfirmed
    (the region was not enabled, so it could not be checked with the
    authoritative API) and the overall confidence is capped at "medium".

    Args:
        facts: dict of collected boolean/int facts (see design for keys).

    Returns:
        {"verdict": "ready"|"degraded"|"blocked", "blockers": [{"code",
         "severity", "reason"}], "confidence"}
    """
    return compute_deployability_impl(facts)
