# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT License
# See LICENSE file in the project root for full license information.
"""Deterministic assembly of the final JSON contract from gathered facts.

The agent (LLM) only gathers facts into a GatheredFacts object. This module —
pure code, no LLM — computes the deployability verdict and confidence and builds
the documented response contract, so the model can never override them.
"""

from schemas import GatheredFacts
from tools.compute_deployability import compute_deployability_impl
from tools.count_azs import count_azs_impl
from tools.format_response import (
    format_fact_response_impl,
    format_readiness_response_impl,
)


def assemble_contract(facts: GatheredFacts) -> dict:
    """Turn gathered facts into the final contract dict (verdict decided here)."""
    azs = [
        {"az_id": z.az_id, **({"az_name": z.az_name} if z.az_name else {})}
        for z in facts.availability_zones
    ]

    if facts.query_mode == "fact":
        return format_fact_response_impl(
            dataset=facts.fact_dataset or "unknown",
            result=_fact_result(facts, azs),
            source=facts.fact_source,
            confidence=facts.fact_confidence,
            region=facts.region,
        )

    # readiness: the core facts must have actually been gathered. If they are
    # missing (None), gathering failed — do NOT fabricate a verdict from empty
    # data (which would otherwise read as spurious insufficient-azs / no-registry
    # blockers). Return a structured error instead.
    required = {
        "region_exists": facts.region_exists,
        "ec2_available": facts.ec2_available,
        "ami_available": facts.ami_available,
    }
    missing = [name for name, value in required.items() if value is None]
    if not facts.availability_zones:
        missing.append("availability_zones")
    if missing:
        from tools.format_response import format_error_response_impl

        return format_error_response_impl(
            "incomplete_facts",
            "The agent could not gather the required facts for a readiness "
            f"verdict (missing: {', '.join(sorted(set(missing)))}).",
        )

    # readiness: compute verdict deterministically from the gathered facts.
    az_count = count_azs_impl(azs).get("count", 0)
    verdict = compute_deployability_impl(
        {
            "region_exists": facts.region_exists if facts.region_exists is not None else True,
            "ec2_available": facts.ec2_available if facts.ec2_available is not None else True,
            "eks_required": facts.eks_required,
            "eks_available": facts.eks_available if facts.eks_available is not None else True,
            "ami_available": facts.ami_available if facts.ami_available is not None else True,
            "eks_ecr_registry_present": facts.eks_ecr_registry is not None,
            "az_count": az_count,
            "instance_type_required": facts.instance_type is not None,
            "instance_type_offered": (
                facts.instance_type_offered
                if facts.instance_type_offered is not None
                else True
            ),
            "instance_type_offered_source": facts.instance_type_offered_source,
            "source_confidences": facts.source_confidences,
        }
    )

    target = {}
    if facts.instance_type:
        target["instance_type"] = facts.instance_type
    if facts.eks_version:
        target["eks_version"] = facts.eks_version

    return format_readiness_response_impl(
        region=facts.region or "",
        verdict=verdict["verdict"],
        blockers=verdict["blockers"],
        facts={
            "region": {"code": facts.region, "long_name": facts.region_long_name},
            "availability_zones": {
                "azs": azs,
                "az_count": az_count,
                "az_names_available": facts.az_names_available,
            },
            "services": {"ec2": facts.ec2_available, "eks": facts.eks_available},
            "ami": {"ami_available": facts.ami_available},
            "instance_type": {
                "name": facts.instance_type,
                "offered": facts.instance_type_offered,
                "source": facts.instance_type_offered_source,
            },
            "eks_ecr_registry": facts.eks_ecr_registry,
        },
        confidence=verdict["confidence"],
        target=target or None,
    )


def _fact_result(facts: GatheredFacts, azs: list) -> dict:
    """Best-effort structured result payload for a fact-mode query."""
    if facts.fact_dataset == "availability_zones":
        return {"azs": azs, "az_names_available": facts.az_names_available}
    # Generic passthrough of whatever single fact was gathered.
    return {
        k: v
        for k, v in {
            "region_exists": facts.region_exists,
            "region_long_name": facts.region_long_name,
            "ec2_available": facts.ec2_available,
            "eks_available": facts.eks_available,
            "ami_available": facts.ami_available,
            "instance_type_offered": facts.instance_type_offered,
            "eks_ecr_registry": facts.eks_ecr_registry,
        }.items()
        if v is not None
    }
